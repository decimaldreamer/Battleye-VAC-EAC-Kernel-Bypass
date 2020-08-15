#pragma once

#include <math.h>

#define M_PI 3.14159265358979323846264338327950288419716939937510


class Vector2
{
public:
	Vector2() : x(0.f), y(0.f)
	{

	}

	Vector2(float _x, float _y) : x(_x), y(_y)
	{

	}
	~Vector2()
	{

	}

	float x;
	float y;
};


class Vector3
{
public:
	Vector3() : x(0.f), y(0.f), z(0.f)
	{

	}

	Vector3(float _x, float _y, float _z) : x(_x), y(_y), z(_z)
	{

	}
	~Vector3()
	{

	}

	float x;
	float y;
	float z;

	inline float Dot(Vector3 v)
	{
		return x * v.x + y * v.y + z * v.z;
	}

	inline float Distance(Vector3 v)
	{
		return float(sqrtf(powf(v.x - x, 2.0) + powf(v.y - y, 2.0) + powf(v.z - z, 2.0)));
	}

	Vector3 operator+(Vector3 v)
	{
		return Vector3(x + v.x, y + v.y, z + v.z);
	}

	Vector3 operator-(Vector3 v)
	{
		return Vector3(x - v.x, y - v.y, z - v.z);
	}

	Vector3 operator*(float number) const
	{
		return Vector3(x * number, y * number, z * number);
	}
};


class Vector4
{
public:
	Vector4() : x(0.f), y(0.f), z(0.f), w(0.f)
	{

	}

	Vector4(float _x, float _y, float _z, float _w) : x(_x), y(_y), z(_z), w(_w)
	{

	}
	~Vector4()
	{

	}

	float x;
	float y;
	float z;
	float w;
};