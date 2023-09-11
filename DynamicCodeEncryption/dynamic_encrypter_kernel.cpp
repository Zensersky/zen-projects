#include "dynamic_encrypter_kernel.h"

//protected_func func1 = { 0, 0, 0, 0, 0};

int dynamic_encrypter_kernel::function_list_count = 0;
//protected_func dynamic_encrypter::function_list[MAX_FUNCTIONS] = { };
protected_func* dynamic_encrypter_kernel::function_list = nullptr;
int dynamic_encrypter_kernel::current_context_stack_count = 0;
protected_func* dynamic_encrypter_kernel::current_context_stack[MAX_FUNCTIONS];

protected_func* dynamic_encrypter_kernel::current_executing_function = nullptr;

__declspec(noinline) PVOID dynamic_encrypter_kernel::get_next_executing_instr()
{
	return _ReturnAddress();
}