namespace fixture {

class Worker {
public:
    __attribute__((noinline)) int compute(int value);
};

int Worker::compute(int value)
{
    if (value > 10) {
        return value - 3;
    }
    return value + 5;
}

__attribute__((noinline)) int call_worker(int value)
{
    Worker worker;
    return worker.compute(value);
}

} // namespace fixture

int main(int argc, char** argv)
{
    const int value = argc > 1 ? argv[1][0] : 4;
    return fixture::call_worker(value);
}
