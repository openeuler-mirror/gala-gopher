import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import jdk.internal.org.objectweb.asm.*;
import jdk.internal.org.objectweb.asm.commons.AdviceAdapter;

import static jdk.internal.org.objectweb.asm.Opcodes.*;

public class ProfilingTransformer implements ClassFileTransformer {

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        try {
            className = className.replace("/", ".");
            if (!"sun.security.ssl.SSLSocketImpl$AppOutputStream".equals(className) &&
                !"sun.security.ssl.SSLSocketImpl$AppInputStream".equals(className)) {
                return classfileBuffer;
            }
            return getBytes(loader, className, classfileBuffer);
        } catch (Throwable e) {
            System.out.println(e.getMessage());
        }
        return classfileBuffer;
    }

    private byte[] getBytes(ClassLoader loader, String className, byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ProfilingClassAdapter(cw, className);
        cr.accept(cv, ClassReader.EXPAND_FRAMES);

        return cw.toByteArray();
    }

    static class ProfilingClassAdapter extends ClassVisitor {
        private String className;

        public ProfilingClassAdapter(final ClassVisitor cv, String innerClassName) {
            super(ASM5, cv);
            this.className = innerClassName;
        }

        public MethodVisitor visitMethod(int access,
                                         String name,
                                         String desc,
                                         String signature,
                                         String[] exceptions) {

            if (("read".equals(name) && desc.contains("[B") == true) ||
                ("write".equals(name) && desc.contains("[B") == true)) {
                MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
                return new ProfilingMethodVisitor(access, name, desc, mv);
            }

            return super.visitMethod(access, name, desc, signature, exceptions);
        }
    }

    static class ProfilingMethodVisitor extends AdviceAdapter {

        private String Pid;
        private String metricTmpFile;
        private int maxLocalSlot;
        private int slotOfb;
        private int slotOfoff;
        private int slotOflen;
        private String rwType;

        protected ProfilingMethodVisitor(int access, String methodName, String descriptor, MethodVisitor methodVisitor) {
            super(ASM5, methodVisitor, access, methodName, descriptor);

            /* public void write(byte[] b, int off, int len) {...}
               public int read(byte[] b, int off, int len) {...} */
            this.slotOfb = 1;
            this.slotOfoff = 2;
            if ("write".equals(methodName)) {
                this.slotOflen = 3; // write，入参len即是真实buffer长度
                this.maxLocalSlot = 6;
                this.rwType = "Write";
            } else if ("read".equals(methodName)) {
                this.slotOflen = 7; // read，返回值(对应局部变量volume)才是真实buffer长度
                this.maxLocalSlot = 9;
                this.rwType = "Read";
            }

            this.metricTmpFile = ArgsParse.getArgMetricTmpFile();
            this.Pid = ArgsParse.getArgPid();

        }

        @Override
        protected void onMethodExit(int opcode) {

            // RandomAccessFile raf = new RandomAccessFile(this.metricTmpFile, "rw");
            mv.visitTypeInsn(NEW, "java/io/RandomAccessFile");
            mv.visitInsn(DUP);
            mv.visitLdcInsn(this.metricTmpFile);
            mv.visitLdcInsn("rw");
            mv.visitMethodInsn(INVOKESPECIAL, "java/io/RandomAccessFile", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", false);
            mv.visitVarInsn(ASTORE, maxLocalSlot + 1);
            // FileChannel fileChannel = raf.getChannel();
            mv.visitVarInsn(ALOAD, maxLocalSlot + 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "getChannel", "()Ljava/nio/channels/FileChannel;", false);
            mv.visitVarInsn(ASTORE, maxLocalSlot + 2);
            // FileLock lock = fileChannel.lock();  // 获取独占锁，无法获取会一直等待
            mv.visitVarInsn(ALOAD, maxLocalSlot + 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/nio/channels/FileChannel", "lock", "()Ljava/nio/channels/FileLock;", false);
            mv.visitVarInsn(ASTORE, maxLocalSlot + 3);
            // raf.seek(raf.length());
            mv.visitVarInsn(ALOAD, maxLocalSlot + 1);
            mv.visitVarInsn(ALOAD, maxLocalSlot + 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "length", "()J", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "seek", "(J)V", false);
            // raf.write(String.format("|jsse_msg|%s|%d|%s|", this.Pid, System.currentTimeMillis(), "Read").getBytes());
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 1);
            mv.visitLdcInsn("|jsse_msg|%s|%d|%s|");
            mv.visitInsn(ICONST_3);
            mv.visitTypeInsn(ANEWARRAY, "java/lang/Object");
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_0);
            mv.visitLdcInsn(this.Pid);
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_1);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false);
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_2);
            mv.visitLdcInsn(this.rwType);
            mv.visitInsn(AASTORE);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/String", "format", "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "write", "([B)V", false);
            // raf.write(b, off, len);
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 1);
            mv.visitVarInsn(ALOAD, this.slotOfb);
            mv.visitVarInsn(ILOAD, this.slotOfoff);
            mv.visitVarInsn(ILOAD, this.slotOflen);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "write", "([BII)V", false);
            // 如果有新增的metric，建议在这里补充

            // raf.write("|\r\n".getBytes());
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 1);
            mv.visitLdcInsn("|\n");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "write", "([B)V", false);
            // lock.release();
            mv.visitVarInsn(ALOAD, maxLocalSlot + 3);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/nio/channels/FileLock", "release", "()V", false);
            // raf.close();
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "close", "()V", false);
        }
    }

}