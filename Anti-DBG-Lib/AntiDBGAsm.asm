PUBLIC _NtGlobalFlagPEBx64
PUBLIC _RDTSCx64
PUBLIC _QueryPerformanceCounterx64
PUBLIC _IntException

.code

_NtGlobalFlagPEBx64 PROC
xor rax, rax                
mov rax, gs:[60h]           
mov rax, [rax + 0BCh]       
and rax, 70h                
ret	               
_NtGlobalFlagPEBx64 ENDP

_RDTSCx64 PROC
rdtsc                             
mov [rcx + 00h], rdx        
mov [rcx + 08h], rax        
xor rax, rax                
mov rax, 5                  
shr rax, 2                  
sub rax, rbx                
cmp rax, rcx                
rdtsc                       
mov [rcx + 10h], rdx        
mov [rcx + 18h], rax        
ret
_RDTSCx64 ENDP

_QueryPerformanceCounterx64 PROC
xor rax, rax
push rax    
push rcx    
pop rax     
pop rcx     
sub rcx, rax
shl rcx, 4  
ret
_QueryPerformanceCounterx64 ENDP


_IntException PROC
int 1h
ret
_IntException ENDP

end