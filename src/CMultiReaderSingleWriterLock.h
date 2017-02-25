#pragma once

#include <Windows.h>
#include <mutex>
#include <atomic>

// the following is based on: http://www.glennslayden.com/code/win32/reader-writer-lock

class CMultiReaderSingleWriterLock : private std::mutex
{
private:
	std::atomic<int64_t> m_readers;
	HANDLE m_hevReadersCleared;

public:
	CMultiReaderSingleWriterLock()
		: std::mutex(), m_readers(0)
	{
		m_hevReadersCleared = ::CreateEvent(NULL, TRUE, TRUE, NULL);
	}

	virtual ~CMultiReaderSingleWriterLock() {
		::WaitForSingleObject(m_hevReadersCleared, INFINITE);
		::CloseHandle(m_hevReadersCleared);
	}

	void EnterReader() {
		lock(); // wait for Writers to finish
		if (++m_readers == 1)
			::ResetEvent(m_hevReadersCleared);
		unlock();
	}

	void LeaveReader() {
		if (--m_readers == 0)
			::SetEvent(m_hevReadersCleared);
	}

	void EnterWriter() {
		lock();
		::WaitForSingleObject(m_hevReadersCleared, INFINITE);
	}

	void LeaveWriter() {
		unlock();
	}
};
