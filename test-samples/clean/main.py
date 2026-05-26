"""Tiny benign module. Pure arithmetic, no I/O beyond print."""


def add(a, b):
    return a + b


def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


if __name__ == "__main__":
    print("2 + 3 =", add(2, 3))
    print("fib(10) =", fibonacci(10))
