#pragma once
#include <Windows.h>
#include <vector>
#include <ctime>

#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

#define DBG_STOP DebugBreak

//Does not support multi_threaded functions

enum eXOR_SEGMENT_TYPE
{
    XOR_SEGMENT_FULL,
    XOR_SEGMENT_FIST_HALF,
    XOR_SEGMENT_SECOND_HALF,
};

struct protected_func
{
    PVOID func_start;
    PVOID func_end;
    bool is_encrypted = false;
    DWORD key;

    DWORD partial_enc_size = 0;
public:
    __forceinline protected_func(PVOID start, PVOID end)
    {
        func_start = start;
        func_end = end;
        key = (__int64)time(NULL) % 0xFF + 0x1;
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

        size_t size = (DWORD64)new_end - (DWORD64)new_start;

        DWORD old_prot;
        VirtualProtect(new_start, size, PAGE_EXECUTE_READWRITE, &old_prot);

        BYTE* c_byte = reinterpret_cast<BYTE*>(new_start);
        for (size_t i = 0; i < size; i++)
        {
            c_byte[i] ^= key;
        }
        VirtualProtect(new_start, size, old_prot, &old_prot);
    }
};

class dynamic_encrypter;
extern dynamic_encrypter dynamic_protector;

class dynamic_encrypter
{
public:
    std::vector<protected_func> function_list;
    std::vector<protected_func*> current_context_stack;

    protected_func* current_executing_function = nullptr;
private:
    __forceinline protected_func* find_func_entry(PVOID function)
    {
        for (auto& func : function_list)
        {
            if (func.func_start == function)
                return &func;

            if (!func.func_end)
                continue;
            if ((DWORD64)func.func_start <= (DWORD64)function && (DWORD64)func.func_end >= (DWORD64)function)
                return &func;
        }
        return nullptr;
    }
public:
    __forceinline void start_protection(const PVOID& func_start)
    {
        auto target_func = find_func_entry(func_start);
        current_executing_function = target_func;
        if (!target_func)
        {
            //First time execution
            protected_func new_prot_func(func_start, nullptr);
            new_prot_func.is_encrypted = false;
            function_list.push_back(new_prot_func);
            current_executing_function = &function_list.at(function_list.size() - 1);
            memset(&new_prot_func, 00, sizeof(protected_func));
        }

        //Possibly only check the previous entry?
        size_t stack_size = this->current_context_stack.size();

        if (stack_size)
        {
            auto& stack_func = this->current_context_stack.at(this->current_context_stack.size() - 1);
            {

                if (stack_func->is_encrypted)
                    return;

                stack_func->xor_segment(XOR_SEGMENT_SECOND_HALF);
                stack_func->is_encrypted = true;
            }
        }
    }
    __declspec(noinline) PVOID get_next_executing_instr()
    {
        return _ReturnAddress();
    }

    static __declspec(noinline) void end_protection(const PVOID& func_start)
    {
        auto target_func = dynamic_protector.find_func_entry(func_start);

        if (!target_func)
            DBG_STOP();

        target_func->func_end = _ReturnAddress();

        const int stack_size = dynamic_protector.current_context_stack.size();
        if (stack_size > 0)
        {
            protected_func* return_to_func = dynamic_protector.current_context_stack.at(stack_size - 1);
            if (return_to_func->is_encrypted)
            {
                return_to_func->xor_segment();
                return_to_func->is_encrypted = false;
            }
            dynamic_protector.current_context_stack.pop_back();
        }
       

    }
    template<typename T, class... Types> __forceinline T safe_call(PVOID func, Types&&... args)
    {
        PVOID enc_point_end = get_next_executing_instr();

        bool first_time = false;
        typedef T(__stdcall* _func)(Types...);
        _func function = (_func)func;

        protected_func* prot_func_entry = this->find_func_entry(func);


        {
            //Actually the current function since this shit is inlined
            PVOID ret_add = get_next_executing_instr();
            if (auto prev_prot_func = this->find_func_entry(ret_add))
            {

                current_context_stack.push_back(prev_prot_func);
                prev_prot_func->partial_enc_size = (DWORD64)enc_point_end - (DWORD64)prev_prot_func->func_start;
                prev_prot_func->xor_segment(XOR_SEGMENT_FIST_HALF);

            }
        }

        T ret;
        if (!prot_func_entry)
        {

            ret = function(args...);

            prot_func_entry = this->find_func_entry(func);

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
        auto resolve_relative_address = [](PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize) -> PVOID
        {
            ULONG RipOffset = *reinterpret_cast<ULONG*>(((uintptr_t)Instruction + OffsetOffset));
            PVOID ResolveAddr = reinterpret_cast<PVOID>((uintptr_t)Instruction + InstructionSize + RipOffset);

            return ResolveAddr;
        };
        

        size_t bytes_till_end = 0;
        BYTE* c_byte = reinterpret_cast<BYTE*>(func);
        for (size_t i = 0; i < 0x10000; i++)
        {
            if (c_byte[i] != 0xE8)
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
            DBG_STOP();
            return;
        }

        protected_func new_prot_func(func, reinterpret_cast<PVOID>((DWORD64)func + bytes_till_end));

        new_prot_func.is_encrypted = true;
        function_list.push_back(new_prot_func);
        new_prot_func.xor_segment();

        memset(&new_prot_func, 00, sizeof(protected_func));
    }
};
