# Introduction to gala-gopher

gala-gopher provides a CUnit-based unit test framework and implements basic function tests on the probe framework, the start/stop of native/extend probes, and metric observation.

## CUnit Overview

CUnit is a system for writing, managing, and running unit tests in C. It is built as a static library that links to user test code. CUnit is a combination of a platform-independent framework and various user interfaces. The core framework provides basic support for managing the test registry, suites, and test cases. The user interfaces facilitate interaction with the framework to run tests and view results.

CUnit is organized in a way similar to conventional unit test frameworks:

```shell
                      Test registry
                            |
             ------------------------------
             | |
          Test suite 1 . . . . Test suite N
             | |
       --------------- ---------------
       | | | |
    Test case 11 ... Test case 1M Test case N1 ... Test case NM
```

For details about CUnit, see <http://cunit.sourceforge.net/doc/introduction.html>.

## gala-gopher Test Framework

gala-gopher encapsulates the CUnit test framework for the probe engine. Currently, there are two test modules:

- test_modules

  Checks whether the function API logic of each basic component in the probe engine meets the expectation. Each basic component corresponds to a test suite, and test cases are defined for each test component.

- test_probes

  Tests the scheduling, startup, and metric information of the probe programs, and check whether the probes meet the expectation based on the probe meta.

The code directory is as follows:

```shell
gala-gopher
├── test     // Test directory
│   ├── test_modules   // Testing submodules of the probe engine
│   │   ├── CMakeLists.txt
│   │   ├── main.c    // Main function for running the test module
│   │   ├── test_fifo.c   // fifo test suite and test case definitions
│   │   ├── test_fifo.h
│   │   ├── test_imdb.c
│   │   ├── test_imdb.h
│   │   ├── test_kafka.c
│   │   ├── test_kafka.h
│   │   ├── test.meta
│   │   ├── test_meta.c
│   │   ├── test_meta.h
│   │   ├── test_probe.c
│   │   └── test_probe.h
│   ├── test_modules.sh   // Running the modules test suite
│   ├── test_probes   // Testing the probe scheduling module
│   │   ├── CMakeLists.txt
│   │   ├── main.c   // Main function for running the test module
│   │   ├── test_probes.c
│   │   └── test_probes.h
│   └── test_probes.sh
└── third_part
```

## Method of Adding a CUnit Test Case

The process of adding a test suite and a test case to a test module is the same as that of adding an existing test case. The following uses the test_fifo test suite as an example.

1. Add a test suite.

   - Select the test module to which the test suite is to be added, for example, test_modules. Define the test suite file **test_fifo.c** in the directory and define the entry function of the test suite.

     ```c
     #define TEST_SUITE_FIFO \
         {   \
             .suiteName = "TEST_FIFO",   \
             .suiteMain = TestFifoMain   \
         }
     ```

   - Add the test_fifo test suite to the main process of the test module and ensure that the test suite is registered properly.

     ```c
     TestSuite gTestSuites[] = {
         TEST_SUITE_FIFO,
         TEST_SUITE_META,
         TEST_SUITE_PROBE,
         TEST_SUITE_IMDB
     };
     ```

     `gTestSuites` will call `CU_add_suite` in the `main` entry of the test module to register with the CUnit test framework.

2. Add a test case.

   - Define the test case `TestFifoGet` of the tested function in the test suite file **test_fifo.c**.

     ```c
     void TestFifoGet()
     {
         uint32_t ret = 0;
         uint32_t elem = 1;
         uint32_t *elemP = NULL;
         Fifo *fifo = FifoCreate(FIFO_SIZE);
     
         CU_ASSERT(fifo != NULL);
         ret = FifoPut(fifo, &elem);
         CU_ASSERT(ret == 0);
         ret = FifoGet(fifo, (void **) &elemP);
         CU_ASSERT(ret == 0);
         CU_ASSERT(fifo->out == 1);
         FifoDestroy(fifo);
     }
     ```

   - Add the test case `TestFifoGet` to the test_fifo test suite.

     ```c
     void TestFifoMain(CU_pSuite suite)
     {
         CU_ADD_TEST(suite, TestFifoGet);
     }
     ```

3. Run the test.

   Run the one-click test script corresponding to the test module in the **test** directory.

   ```sh
   cd test/
   [root@localhost test]# ./test_modules.sh
   ```
