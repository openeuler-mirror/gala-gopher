import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.io.File;
import java.io.IOException;
import java.security.ProtectionDomain;
import jdk.internal.org.objectweb.asm.*;
import jdk.internal.org.objectweb.asm.commons.AdviceAdapter;

import static jdk.internal.org.objectweb.asm.Opcodes.*;

public class ProfilingTransformer implements ClassFileTransformer {

    public boolean isWriteTransformed = false;
    public boolean isReadTransformed = false;

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        try {
            className = className.replace("/", ".");
            if ("sun.security.ssl.SSLSocketImpl$AppOutputStream".equals(className)) {
                createTmpFile();
                if (!isWriteTransformed) {
                    // ensure only transform once even if javaagent be loaded multiple times.
                    isWriteTransformed = true;
                    return getBytes(loader, className, classfileBuffer);
                }
            }
            if ("sun.security.ssl.SSLSocketImpl$AppInputStream".equals(className)) {
                createTmpFile();
                if (!isReadTransformed) {
                    isReadTransformed = true;
                    return getBytes(loader, className, classfileBuffer);
                }
            }
        } catch (Throwable e) {
            System.out.println(e.getMessage());
        }
        return classfileBuffer;
    }

    private static void createTmpFile() throws IOException {
        File tmpDirectory = new File(ArgsParse.getArgMetricDataPath());
        if (!tmpDirectory.exists()) {
            tmpDirectory.mkdir();
        }
        File metricTmpFile = new File(ArgsParse.getArgMetricTmpFile());
        if (!metricTmpFile.exists()) {
            metricTmpFile.createNewFile();
        }
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
        private String className;

        protected ProfilingMethodVisitor(int access, String methodName, String descriptor, MethodVisitor methodVisitor) {
            super(ASM5, methodVisitor, access, methodName, descriptor);

            /* public void write(byte[] b, int off, int len) {...}
               public int read(byte[] b, int off, int len) {...} */
            this.slotOfb = 1;
            this.slotOfoff = 2;
            if ("write".equals(methodName)) {
                this.slotOflen = 3; // write, the input parameter len is the real buffer length
                this.maxLocalSlot = 6;
                this.rwType = "Write";
                this.className = "sun/security/ssl/SSLSocketImpl$AppOutputStream";
            } else if ("read".equals(methodName)) {
                this.slotOflen = 7; // read, the return value(local var "volume") is the real buffer length
                this.maxLocalSlot = 9;
                this.rwType = "Read";
                this.className = "sun/security/ssl/SSLSocketImpl$AppInputStream";
            }

            this.metricTmpFile = ArgsParse.getArgMetricTmpFile();
            this.Pid = ArgsParse.getArgPid();
        }

        // eg. |jsse_msg|662220|Session(1688648699909|TLS_AES_256_GCM_SHA384)|1688648699989|Write|s|127.0.0.1|58302|This is test message|
        @Override
        protected void onMethodExit(int opcode) {
            // char mode = getUseClientMode() ? 'c' : 's';
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, this.className, "this$0", "Lsun/security/ssl/SSLSocketImpl;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "sun/security/ssl/SSLSocketImpl",  "getUseClientMode", "()Z", false);
            Label l1 = new Label();
            mv.visitJumpInsn(IFEQ, l1);
            mv.visitIntInsn(BIPUSH, 99); // 99 = 'c'
            Label l2 = new Label();
            mv.visitJumpInsn(GOTO, l2);
            mv.visitLabel(l1);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitIntInsn(BIPUSH, 115); // 115 = 's'
            mv.visitLabel(l2);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[]{Opcodes.INTEGER});
            mv.visitVarInsn(ISTORE, maxLocalSlot + 1);

            // create labels
            Label labelIf = new Label();
            Label labelEnd = new Label();

            // if new File(this.metricTmpFile).exists()
            mv.visitTypeInsn(NEW, "java/io/File");
            mv.visitInsn(DUP);
            mv.visitLdcInsn(this.metricTmpFile);
            mv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "exists", "()Z", false);
            // if File.exists == 0 jump to labelEnd (make sure the "If block" comes first)
            mv.visitJumpInsn(IFEQ, labelEnd);
            // If block
            mv.visitLabel(labelIf);
            // RandomAccessFile raf = new RandomAccessFile(this.metricTmpFile, "rw");
            mv.visitTypeInsn(NEW, "java/io/RandomAccessFile");
            mv.visitInsn(DUP);
            mv.visitLdcInsn(this.metricTmpFile);
            mv.visitLdcInsn("rw");
            mv.visitMethodInsn(INVOKESPECIAL, "java/io/RandomAccessFile", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", false);
            mv.visitVarInsn(ASTORE, maxLocalSlot + 2);
            // FileChannel fileChannel = raf.getChannel();
            mv.visitVarInsn(ALOAD, maxLocalSlot + 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "getChannel", "()Ljava/nio/channels/FileChannel;", false);
            mv.visitVarInsn(ASTORE, maxLocalSlot + 3);
            // FileLock lock = fileChannel.lock(); (will block until holding the lock)
            mv.visitVarInsn(ALOAD, maxLocalSlot + 3);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/nio/channels/FileChannel", "lock", "()Ljava/nio/channels/FileLock;", false);
            mv.visitVarInsn(ASTORE, maxLocalSlot + 4);
            // raf.seek(raf.length());
            mv.visitVarInsn(ALOAD, maxLocalSlot + 2);
            mv.visitVarInsn(ALOAD, maxLocalSlot + 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "length", "()J", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "seek", "(J)V", false);

            // raf.write(String.format("|jsse_msg|%s|%s|%d|%s|%c|%s|%d|", this.Pid, getSession(), System.currentTimeMillis(), "Read", mode, getInetAddress().getHostAddress(), getPeerPort()).getBytes());
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 2);
            mv.visitLdcInsn("|jsse_msg|%s|%s|%d|%s|%c|%s|%d|");
            mv.visitIntInsn(BIPUSH, 7);
            mv.visitTypeInsn(ANEWARRAY, "java/lang/Object");

            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_0);
            mv.visitLdcInsn(this.Pid);
            mv.visitInsn(AASTORE);

            // Use SSLSession because socket fd is private so hard to access
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_1);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, this.className, "this$0", "Lsun/security/ssl/SSLSocketImpl;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "sun/security/ssl/SSLSocketImpl",  "getSession", "()Ljavax/net/ssl/SSLSession;", false);
            mv.visitInsn(AASTORE);

            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_2);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false);
            mv.visitInsn(AASTORE);

            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_3);
            mv.visitLdcInsn(this.rwType);
            mv.visitInsn(AASTORE);

            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_4);
            mv.visitVarInsn(ILOAD, maxLocalSlot + 1);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false);
            mv.visitInsn(AASTORE);

            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_5);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, this.className, "this$0", "Lsun/security/ssl/SSLSocketImpl;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "sun/security/ssl/SSLSocketImpl", "getInetAddress", "()Ljava/net/InetAddress;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/InetAddress", "getHostAddress", "()Ljava/lang/String;", false);
            mv.visitInsn(AASTORE);

            mv.visitInsn(DUP);
            mv.visitIntInsn(BIPUSH, 6);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, this.className, "this$0", "Lsun/security/ssl/SSLSocketImpl;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "sun/security/ssl/SSLSocketImpl", "getPeerPort", "()I", false);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
            mv.visitInsn(AASTORE);

            mv.visitMethodInsn(INVOKESTATIC, "java/lang/String", "format", "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "write", "([B)V", false);
            // raf.write(b, off, len);
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 2);
            mv.visitVarInsn(ALOAD, this.slotOfb);
            mv.visitVarInsn(ILOAD, this.slotOfoff);
            mv.visitVarInsn(ILOAD, this.slotOflen);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "write", "([BII)V", false);
            // New Metrics can be added here if exist

            // raf.write("|\r\n".getBytes());
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 2);
            mv.visitLdcInsn("|\n");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "write", "([B)V", false);
            // lock.release();
            mv.visitVarInsn(ALOAD, maxLocalSlot + 4);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/nio/channels/FileLock", "release", "()V", false);
            // raf.close();
            mv.visitVarInsn(ALOAD, this.maxLocalSlot + 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/RandomAccessFile", "close", "()V", false);

            // End
            mv.visitLabel(labelEnd);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[] { "java/lang/String" });
        }
    }

}