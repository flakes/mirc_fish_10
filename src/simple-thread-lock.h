#pragma once

#include <Windows.h>

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
