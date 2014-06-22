#pragma once

#include <Windows.h>
#include <atomic>

class CSimpleThreadLock
{
public:
	CSimpleThreadLock() {
		::InitializeCriticalSection(&m_crt_sec);
	}

	virtual ~CSimpleThreadLock() {
		::DeleteCriticalSection(&m_crt_sec);
	}

	void Lock() const {
		::EnterCriticalSection(&m_crt_sec);
	}

	void Unlock() const {
		::LeaveCriticalSection(&m_crt_sec);
	}

private:
	mutable CRITICAL_SECTION m_crt_sec;
};

class CSimpleScopedLock
{
public:
	CSimpleScopedLock(const CSimpleThreadLock& lock) : m_lock(&lock) {
		m_lock->Lock();
	}
	~CSimpleScopedLock() {
		m_lock->Unlock();
	}

private:
	const CSimpleThreadLock* m_lock;
};

// the following is based on: http://www.glennslayden.com/code/win32/reader-writer-lock

class CMultiReaderSingleWriterLock : private CSimpleThreadLock
{
private:
	std::atomic<int64_t> m_readers;
	HANDLE m_hevReadersCleared;

public:
	CMultiReaderSingleWriterLock()
		: CSimpleThreadLock(), m_readers(0)
	{
		m_hevReadersCleared = ::CreateEvent(NULL, TRUE, TRUE, NULL);
	}

	virtual ~CMultiReaderSingleWriterLock() {
		::WaitForSingleObject(m_hevReadersCleared, INFINITE);
		::CloseHandle(m_hevReadersCleared);
	}

	void EnterReader() {
		Lock(); // wait for Writers to finish
		if (++m_readers == 1)
			::ResetEvent(m_hevReadersCleared);
		Unlock();
	}

	void LeaveReader() {
		if (--m_readers == 0)
			::SetEvent(m_hevReadersCleared);
	}

	void EnterWriter() {
		Lock();
		::WaitForSingleObject(m_hevReadersCleared, INFINITE);
	}

	void LeaveWriter() {
		Unlock();
	}
};
