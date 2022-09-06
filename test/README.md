# gala-gopher测试框架介绍

gala-gopher提供了基于CUint的单元测试框架，并实现了探针框架、native/extends探针的启停、指标观测的基本功能测试；

## 什么是CUint

CUnit是一个用于在C中编写，管理和运行单元测试的系统，它被构建为一个与用户测试代码链接的静态库。CUnit是一个平台无关框架与各种用户界面的组合。核心框架为管理测试注册表，套件和测试用例提供了基本支持。用户界面便于与框架交互以运行测试和查看结果。 

CUnit 的组织方式类似于传统的单元测试框架：

```shell
                      测试注册
                            |
             ------------------------------
             | |
          测试套1. . . . 测试套N
             | |
       --------------- ---------------
       | | | |
    测试例11 ... 测试例1M 测试例 N1 ... 测试例 NM
```

详细CUint的介绍参考：http://cunit.sourceforge.net/doc/introduction.html

## gala-gopher测试框架

gala-gopher对于探针引擎封装了CUint测试框架，当前分为两个测试模块：

- test_modules

  测试探针引擎中各个基础部件的函数API逻辑是否符合预期；各个基础部件对应不同的测试套，每个测试部件中定义测试例进行测试；

- test_probes

  对探针程序调度、启动及指标信息做测试，根据probe meta检查探针是否符合预期；

代码目录如下：

```
gala-gopher
├── test					// 测试目录
│   ├── test_modules		 // 测试探针引擎的各个子模块
│   │   ├── CMakeLists.txt
│   │   ├── main.c			 // 测试模块运行主函数
│   │   ├── test_fifo.c		 // fifo测试套、测试例定义
│   │   ├── test_fifo.h
│   │   ├── test_imdb.c
│   │   ├── test_imdb.h
│   │   ├── test_kafka.c
│   │   ├── test_kafka.h
│   │   ├── test.meta
│   │   ├── test_meta.c
│   │   ├── test_meta.h
│   │   ├── test_probe.c
│   │   └── test_probe.h
│   ├── test_modules.sh		 // 运行modules测试套
│   ├── test_probes			// 测试探针调度模块
│   │   ├── CMakeLists.txt
│   │   ├── main.c			// 测试模块运行主函数
│   │   ├── test_probes.c
│   │   └── test_probes.h
│   └── test_probes.sh
└── third_part
```

## 如何增加一个CUint测试例

测试模块中新增测试套、测试例的过程与现有测试例一致，以test_fifo测试套为例做介绍；

1. 增加测试套

   - 选择在哪个测试模块中增加测试套，如test_modules；在目录下新定义一个测试套文件test_fifo.c，并定义测试套入口函数：

     ```c
     #define TEST_SUITE_FIFO \
         {   \
             .suiteName = "TEST_FIFO",   \
             .suiteMain = TestFifoMain   \
         }
     ```

   - 将test_fifo测试套增加到测试模块的主流程中，确保测试套被正常注册：

     ```c
     TestSuite gTestSuites[] = {
         TEST_SUITE_FIFO,
         TEST_SUITE_META,
         TEST_SUITE_PROBE,
         TEST_SUITE_IMDB
     };
     ```

     `gTestSuites `将在测试模块的`main`入口中调用`CU_add_suite `注册到CUint测试框架中；

2. 增加测试例

   - 测试套文件test_fifo.c中定义被测函数的测试例`TestFifoGet`

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

   - 增加`TestFifoGet`测试例到test_fifo测试套中：

     ```c
     void TestFifoMain(CU_pSuite suite)
     {
         CU_ADD_TEST(suite, TestFifoGet);
     }
     ```

3. 运行测试

   直接运行test目录下测试模块对应的一键测试脚本即可；

   ```sh
   cd test/
   [root@localhost test]# ./test_modules.sh
   ```