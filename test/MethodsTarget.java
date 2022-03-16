import java.io.File;

class Target {
    private static volatile int value;

    private static void method1() {
        for (int i = 0; i < 1000; ++i)
            ++value;
    }

    private static void method2() {
        for (int i = 0; i < 1000; ++i)
            ++value;
    }

    private static void method3() {
        for (int i = 0; i < 1000; ++i)
            ++value;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Starting...");
        while (true) {
            method1();
            method2();
            method3();
            Thread.sleep(9);
        }
    }
}
