/*
 * Copyright 2016 Andrei Pangin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _VMENTRY_H
#define _VMENTRY_H

#include <jvmti.h>


#ifdef __clang__
#  define DLLEXPORT __attribute__((visibility("default")))
#else
#  define DLLEXPORT __attribute__((externally_visible))
#endif


enum FrameTypeId {
    FRAME_INTERPRETED  = 0,
    FRAME_JIT_COMPILED = 1,
    FRAME_INLINED      = 2,
    FRAME_NATIVE       = 3,
    FRAME_CPP          = 4,
    FRAME_KERNEL       = 5,
    FRAME_UNKNOWN      = 6,
};

// Denotes ASGCT_CallFrame where method_id has special meaning (not jmethodID)
enum ASGCT_CallFrameType {
    BCI_SMALLEST_USED_BY_VM = -9,   // small negative BCIs are used by the VM (-6 is the smallest currently)
    BCI_NATIVE_FRAME        = -10,  // native function name (char*)
    BCI_ALLOC               = -11,  // name of the allocated class
    BCI_ALLOC_OUTSIDE_TLAB  = -12,  // name of the class allocated outside TLAB
    BCI_LOCK                = -13,  // class name of the locked object
    BCI_PARK                = -14,  // class name of the park() blocker
    BCI_THREAD_ID           = -15,  // method_id designates a thread
    BCI_ERROR               = -16,  // method_id is an error string
    BCI_INSTRUMENT          = -17,  // synthetic method_id that should not appear in the call stack
    BCI_TYPE_MASK           = 0x0f000000 // mask for encoding the frame type (right shift by 24 after masking)
};

// See hotspot/src/share/vm/prims/forte.cpp
enum ASGCT_Failure {
    ticks_no_Java_frame         =  0,
    ticks_no_class_load         = -1,
    ticks_GC_active             = -2,
    ticks_unknown_not_Java      = -3,
    ticks_not_walkable_not_Java = -4,
    ticks_unknown_Java          = -5,
    ticks_not_walkable_Java     = -6,
    ticks_unknown_state         = -7,
    ticks_thread_exit           = -8,
    ticks_deopt                 = -9,
    ticks_safepoint             = -10,
    ticks_skipped               = -11,
    ASGCT_FAILURE_TYPES         = 12
};

// Frame types used for output (output generators use these directly)
enum StoredFrameType {
    FRAME_TYPE_NATIVE           = 'n',
    FRAME_TYPE_ALLOC            = 'a',
    FRAME_TYPE_OUTSIDE_TLAB     = 'o',
    FRAME_TYPE_LOCK             = 'l',
    FRAME_TYPE_PARK             = 'p',
    FRAME_TYPE_THREAD           = 't',
    FRAME_TYPE_ERROR            = 'e',
    FRAME_TYPE_INSTRUMENT       = 's',
    FRAME_TYPE_INTERNALERR      = 'X',
    FRAME_TYPE_INTERPRETED_JAVA = 'I',
    FRAME_TYPE_INLINED_JAVA     = 'i',
    FRAME_TYPE_UNKNOWN_JAVA     = 'j',
    FRAME_TYPE_CPP              = 'p',
    FRAME_TYPE_BOTTOM           = 'b',
    FRAME_TYPE_C1               = '1',
    FRAME_TYPE_C2               = '2',
};

struct ASGCT_CallFrame {
    void *machine_pc;           // program counter, for C and native frames (frames of native methods)
    uint8_t type;               // frame type (single byte)
    uint8_t comp_level;         // highest compilation level of a method related to a Java frame
    // information from original CallFrame
    jint bci;                   // bci for Java frames
    jmethodID method_id;        // method ID for Java frames

    int get_comp_level() {
        return comp_level;
    }

    int get_frame_type() {
        return type;
    }

    bool is_non_java() { return get_frame_type() == FRAME_NATIVE ||
        get_frame_type() == FRAME_KERNEL || get_frame_type() == FRAME_CPP; }
};

int16_t encode_type(int frame_type, int comp_level) {
  return frame_type + (comp_level << 8);
}

struct ASGCT_CallTrace {
    JNIEnv* env;
    jint num_frames;
    ASGCT_CallFrame* frames;
};


// we translate the newer data structures directly into the older ones
// this reduces the number of modification in async-profiler
namespace new_asgct2 {
    enum FrameTypeId : uint8_t {
        FRAME_JAVA         = 1, // JIT compiled and interpreted
        FRAME_JAVA_INLINED = 2, // inlined JIT compiled
        FRAME_NATIVE       = 3, // native wrapper to call C methods from Java
        FRAME_STUB         = 4, // VM generated stubs
        FRAME_CPP          = 5  // C/C++/... frames
    };

    typedef struct {
        FrameTypeId type;            // frame type
        uint8_t comp_level;      // compilation level, 0 is interpreted
        uint16_t bci;            // 0 < bci < 65536
        jmethodID method_id;
    } JavaFrame;               // used for FRAME_JAVA and FRAME_JAVA_INLINED

    typedef struct {
        FrameTypeId type;  // frame type
        void *pc;          // current program counter inside this frame
    } NonJavaFrame;

    typedef union {
        FrameTypeId type;     // to distinguish between JavaFrame and NonJavaFrame
        JavaFrame java_frame;
        NonJavaFrame non_java_frame;
    } CallFrame;

    typedef struct {
        jint num_frames;                // number of frames in this trace
        CallFrame *frames;              // frames
        void* frame_info;               // more information on frames
    } CallTrace;
};


typedef void (*AsyncGetCallTrace)(new_asgct2::CallTrace *trace, jint depth, void* ucontext,
    int32_t options);

typedef struct {
    void* unused[38];
    jstring (JNICALL *ExecuteDiagnosticCommand)(JNIEnv*, jstring);
} VMManagement;

enum CompLevel {
  CompLevel_none              = 0,         // Interpreter
  CompLevel_simple            = 1,         // C1
  CompLevel_limited_profile   = 2,         // C1, invocation & backedge counters
  CompLevel_full_profile      = 3,         // C1, invocation & backedge counters + mdo
  CompLevel_full_optimization = 4          // C2 or JVMCI
};

typedef VMManagement* (*JVM_GetManagement)(jint);

typedef struct {
    void* unused1[86];
    jvmtiError (JNICALL *RedefineClasses)(jvmtiEnv*, jint, const jvmtiClassDefinition*);
    void* unused2[64];
    jvmtiError (JNICALL *RetransformClasses)(jvmtiEnv*, jint, const jclass*);
} JVMTIFunctions;


class VM {
  private:
    static JavaVM* _vm;
    static jvmtiEnv* _jvmti;

    static int _hotspot_version;
    static bool _openj9;

    static jvmtiError (JNICALL *_orig_RedefineClasses)(jvmtiEnv*, jint, const jvmtiClassDefinition*);
    static jvmtiError (JNICALL *_orig_RetransformClasses)(jvmtiEnv*, jint, const jclass* classes);

    static void ready();
    static void* getLibraryHandle(const char* name);
    static void loadMethodIDs(jvmtiEnv* jvmti, JNIEnv* jni, jclass klass);
    static void loadAllMethodIDs(jvmtiEnv* jvmti, JNIEnv* jni);

  public:
    static void* _libjvm;
    static void* _libjava;
    static AsyncGetCallTrace _asyncGetCallTrace;

    static void asyncGetCallTrace(ASGCT_CallTrace *trace, jint max_depth, void *ucontext);

    static JVM_GetManagement _getManagement;

    static bool init(JavaVM* vm, bool attach);

    static void restartProfiler();

    static jvmtiEnv* jvmti() {
        return _jvmti;
    }

    static JNIEnv* jni() {
        JNIEnv* jni;
        return _vm->GetEnv((void**)&jni, JNI_VERSION_1_6) == 0 ? jni : NULL;
    }

    static JNIEnv* attachThread(const char* name) {
        JNIEnv* jni;
        JavaVMAttachArgs args = {JNI_VERSION_1_6, (char*)name, NULL};
        return _vm->AttachCurrentThreadAsDaemon((void**)&jni, &args) == 0 ? jni : NULL;
    }

    static void detachThread() {
        _vm->DetachCurrentThread();
    }

    static VMManagement* management() {
        return _getManagement != NULL ? _getManagement(0x20030000) : NULL;
    }

    static int hotspot_version() {
        return _hotspot_version;
    }

    static bool isOpenJ9() {
        return _openj9;
    }

    static void JNICALL VMInit(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread);
    static void JNICALL VMDeath(jvmtiEnv* jvmti, JNIEnv* jni);

    static void JNICALL ClassLoad(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread, jclass klass) {
        // Needed only for AsyncGetCallTrace support
    }

    static void JNICALL ClassPrepare(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread, jclass klass) {
        loadMethodIDs(jvmti, jni, klass);
    }

    static jvmtiError JNICALL RedefineClassesHook(jvmtiEnv* jvmti, jint class_count, const jvmtiClassDefinition* class_definitions);
    static jvmtiError JNICALL RetransformClassesHook(jvmtiEnv* jvmti, jint class_count, const jclass* classes);
};

jint removeTypeInfoFromFrame(jint bci);

#endif // _VMENTRY_H
