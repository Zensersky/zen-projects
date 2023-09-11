#include <iostream>
#include <Windows.h>
//#include "dynamic_encrypter.h"
#include "dynamic_encrypter_kernel.h"

#include  <chrono>

__int64 some_func_2(__int64 value)
{
    dynamic_encrypter_kernel::start_protection(some_func_2);

    printf("[some_func_2] value = %i\n", value);

    value ^= 0xFF;

    printf("[some_func_2] value = %i\n", value);

    dynamic_encrypter_kernel::end_protection(some_func_2);

    return 0x5FF11;
}

bool some_func(int value, std::string str)
{
    dynamic_encrypter_kernel::start_protection(some_func);

    printf("[some_func] value = %i (%s)\n", value, str.c_str());

    for (int i = 0; i < 2; i++)
    {
        //Can call mutliple safe called functions since protector saves them on stack
        if (value > 0)
            dynamic_encrypter_kernel::safe_call<__int64>(some_func_2, 33);
    }
    dynamic_encrypter_kernel::end_protection(some_func);

    return true;
}

bool null_pfn(PVOID mdl, int a2, int a3, int a4, int a5, int a6, int a7, int a8)
{
    DYNAMIC_PROT_START(null_pfn);
    printf("null_pfn called %i %i %i %i %i %i %i %i!\n", mdl, a2, a3, a4, a5, a6, a7, a8);
    static int sig_break = 0x71;
    if (!mdl)
    {
        DYNAMIC_PROT_END_INLINE(null_pfn);
        return false;
    }


    DYNAMIC_PROT_END(null_pfn);
    return true;
}

void func()
{
    DYNAMIC_PROT_START(func);

    printf("null_pfn : %i\n", SAFE_CALL(bool, null_pfn, nullptr, 1, 2, 3, 4, 5, 6, 7));

    DYNAMIC_PROT_END(func);
}


int main()
{
    //Allocate the list for the functions, done like this, due for it's compatability with kernel
    dynamic_encrypter_kernel::function_list = (protected_func*)VirtualAlloc(nullptr, sizeof(protected_func) * MAX_FUNCTIONS, MEM_COMMIT, PAGE_READWRITE);//new protected_func[MAX_FUNCTIONS];

    //Static protect functions, these functions will get xored until they are called again
    dynamic_encrypter_kernel::static_protect_function(null_pfn);
    dynamic_encrypter_kernel::static_protect_function(func);

    //This function will get xored after being executed, it is valid only for short period
    dynamic_encrypter_kernel::safe_call<bool>(some_func, 15, std::string("Encryption is cool"));

    system("pause");
}

