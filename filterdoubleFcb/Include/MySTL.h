#pragma once

template<class T>
class CArray {
public:
	int size;
	T* I;
	CArray() :size(0) { I = new T[0]; }
	CArray(int _size) {
		size = _size;
		I = new T[_size];
	}
	void resize(int _size) {
		delete[] I;
		size = _size;
		I = new T[_size];
	}
	~CArray() {
		size = 0;
		delete[] I;
	}
	T& operator[] (unsigned int i) {
		return I[i];
	}
};