#pragma once
#include <Windows.h>
#include <intrin.h>
#include <ctime>

#include <iostream>

#pragma warning(disable:4996)

#pragma intrinsic(_ReturnAddress)

#define DBG_STOP DebugBreak()
#define MAX_FUNCTIONS 32

#define USE_DYNAMIC_ENC 1

#if(USE_DYNAMIC_ENC)
#define SAFE_CALL(x, y, ...) dynamic_encrypter_kernel::safe_call<x>(y, __VA_ARGS__)

#define DYNAMIC_PROT_START(x) dynamic_encrypter_kernel::start_protection(x)
#define DYNAMIC_PROT_END(x) dynamic_encrypter_kernel::end_protection(x)
#define DYNAMIC_PROT_END_INLINE(x) dynamic_encrypter_kernel::end_protection_inline(x) // only used if not at the real function ending
#else
#define SAFE_CALL(x, y, ...) y(__VA_ARGS__) 

#define DYNAMIC_PROT_START(x) 
#define DYNAMIC_PROT_END(x)
#define DYNAMIC_PROT_END_INLINE(x)
#endif

enum eXOR_SEGMENT_TYPE
{
    XOR_SEGMENT_FULL,
    XOR_SEGMENT_FIST_HALF,
    XOR_SEGMENT_SECOND_HALF,
};

struct protected_func
{
    PVOID func_start = nullptr;
    PVOID func_end = nullptr;
    bool is_encrypted = false;
    ULONG key = 0x00;

    ULONG partial_enc_size = 0;
public:

    __forceinline protected_func(PVOID start, PVOID end)
    {
        func_start = start;
        func_end = end;

        //RandomNumber
        ULONG seed = (ULONG)0x13188213;

        key = seed % 0xFF + 0x1;
    }

    __forceinline void xor_segment(eXOR_SEGMENT_TYPE partial_xor = XOR_SEGMENT_FULL)
    {
        PVOID new_start = reinterpret_cast<PVOID>((DWORD64)func_start);
        PVOID new_end = reinterpret_cast<PVOID>((DWORD64)func_end);

        switch (partial_xor)
        {
        case XOR_SEGMENT_FIST_HALF:
            new_start = reinterpret_cast<PVOID>(new_start);
            new_end = reinterpret_cast<PVOID>((DWORD64)new_start + partial_enc_size);
            break;
        case XOR_SEGMENT_SECOND_HALF:
            new_start = reinterpret_cast<PVOID>((DWORD64)new_start + partial_enc_size);
            new_end = reinterpret_cast<PVOID>((DWORD64)new_end);
            break;
        default:
            break;
        }

        if (new_start > new_end)
        {
            DBG_STOP;
            return;
        }

        size_t size = (DWORD64)new_end - (DWORD64)new_start;

        ULONG old_prot;
         VirtualProtect(new_start, size, PAGE_EXECUTE_READWRITE, &old_prot);


        char* c_byte = reinterpret_cast<char*>(new_start);
        for (size_t i = 0; i < size; i++)
        {
            c_byte[i] ^= key;
        }
        VirtualProtect(new_start, size, old_prot, &old_prot);
    }
};


namespace dynamic_encrypter_kernel
{

    extern int function_list_count;
    extern protected_func* function_list;
    extern int current_context_stack_count;
    extern protected_func* current_context_stack[MAX_FUNCTIONS];
    extern protected_func* current_executing_function;

    __forceinline protected_func* find_func_entry(PVOID function)
    {
        for (int i = 0; i < function_list_count; i++)
        {
            protected_func* func = &function_list[i];

            if (func->func_start == function)
                return func;

            if (!func->func_end)
                continue;

            if ((DWORD64)func->func_start <= (DWORD64)function && (DWORD64)func->func_end >= (DWORD64)function)
                return func;
        }
        return nullptr;
    }

    __forceinline void start_protection(const PVOID& func_start)
    {
        auto target_func = find_func_entry(func_start);
        current_executing_function = target_func;
        if (!target_func)
        {
            //First time execution
            protected_func new_prot_func(func_start, nullptr);
            new_prot_func.is_encrypted = false;
           
            function_list[function_list_count] = new_prot_func;
            function_list_count++;
            current_executing_function = &function_list[function_list_count - 1];
            memset(&new_prot_func, 00, sizeof(protected_func));
        }

        //Possibly only check the previous entry?
        size_t stack_size = current_context_stack_count;

        if (stack_size)
        {
            auto& stack_func = current_context_stack[current_context_stack_count - 1];
            {
                if (stack_func->is_encrypted)
                    return;

                stack_func->xor_segment(XOR_SEGMENT_SECOND_HALF);
                stack_func->is_encrypted = true;
            }
        }
    }
    __declspec(noinline) PVOID get_next_executing_instr();

    static __declspec(noinline) void end_protection(const PVOID& func_start)
    {
        auto target_func = find_func_entry(func_start);

        target_func->func_end = _ReturnAddress();

        const int stack_size = current_context_stack_count;
        if (stack_size > 0)
        {
            protected_func* return_to_func = current_context_stack[stack_size - 1];
            if (return_to_func->is_encrypted)
            {
                return_to_func->xor_segment();
                return_to_func->is_encrypted = false;
            }
            current_context_stack[current_context_stack_count] = nullptr;
            current_context_stack_count--;
        }


    }
    static __forceinline void end_protection_inline(const PVOID& func_start)
    {
        auto target_func = find_func_entry(func_start);



        const int stack_size = current_context_stack_count;
        if (stack_size > 0)
        {
            protected_func* return_to_func = current_context_stack[stack_size - 1];
            if (return_to_func->is_encrypted)
            {
                return_to_func->xor_segment();
                return_to_func->is_encrypted = false;
            }
            current_context_stack[current_context_stack_count] = nullptr;
            current_context_stack_count--;
        }


    }
    template<typename T, class... Types> __forceinline T safe_call(PVOID func, Types&&... args)
    {
        PVOID enc_point_end = get_next_executing_instr();

        bool first_time = false;
        typedef T(__stdcall* _func)(Types...);
        _func function = (_func)func;

        protected_func* prot_func_entry = find_func_entry(func);

        {
            //Actually the current function since this shit is inlined
            PVOID ret_add = get_next_executing_instr();
            if (auto prev_prot_func = find_func_entry(ret_add))
            {
                current_context_stack[current_context_stack_count] = prev_prot_func;
                current_context_stack_count++;
                prev_prot_func->partial_enc_size = (DWORD64)enc_point_end - (DWORD64)prev_prot_func->func_start;
                prev_prot_func->xor_segment(XOR_SEGMENT_FIST_HALF);
            }
        }

        T ret = T();
        if (!prot_func_entry)
        {
            //It creats protected_func instance in start protection call
            ret = function(args...);

            prot_func_entry = find_func_entry(func);

            if (!prot_func_entry)
                return ret;

            first_time = true;
        }


        //Decrypt the code
        if (prot_func_entry->is_encrypted)
        {
            prot_func_entry->xor_segment();
            prot_func_entry->is_encrypted = false;
        }

        if (!first_time)
            ret = function(args...);

        //Encrypt the code back
        prot_func_entry->is_encrypted = true;
        prot_func_entry->xor_segment();


        return ret;
    }


    __forceinline void static_protect_function(PVOID func)
    {
        auto resolve_relative_address = [](PVOID Instruction, DWORD OffsetOffset, DWORD InstructionSize) -> PVOID
        {
            ULONG_PTR Instr = (ULONG_PTR)Instruction;
            LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
            PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

            return ResolvedAddr;
        };


        size_t bytes_till_end = 0;
        char* c_byte = reinterpret_cast<char*>(func);
        for (size_t i = 0; i < 0x10000; i++)
        {
            if (c_byte[i] != 0xE8 && c_byte[i] != 0xFFFFFFE8)
                continue;

            PVOID resolved_address = resolve_relative_address(&c_byte[i], 1, 5);
            if (resolved_address == end_protection)
            {
                bytes_till_end = i;
                break;
            }
        }

        if (!bytes_till_end)
        {
            DBG_STOP;
            return;
        }

        protected_func new_prot_func(func, reinterpret_cast<PVOID>((DWORD64)func + bytes_till_end));

        new_prot_func.is_encrypted = true;
        function_list[function_list_count] = new_prot_func;
        function_list_count++;
        new_prot_func.xor_segment();

       memset(&new_prot_func, 00, sizeof(protected_func));
    }
};
