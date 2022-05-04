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

#include <array>
#include <bits/types/siginfo_t.h>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include "stackFrame.h"
#include "vmEntry.h"
#include "arguments.h"
#include "j9Ext.h"
#include "j9ObjectSampler.h"
#include "javaApi.h"
#include "os.h"
#include "profiler.h"
#include "instrument.h"
#include "lockTracer.h"
#include "log.h"
#include "vmStructs.h"
#include "pmparser.h"
#include "safeAccess.h"
#include <sys/socket.h>
/*#include "xed/xed-types.h"
#include "xed/xed-state.h"
#include "xed/xed-decoded-inst.h"*/

/*extern "C" {
    void xed_tables_init();
     xed_error_enum_t
xed_ild_decode(xed_decoded_inst_t* xedd,
               const xed_uint8_t* itext,
               const unsigned int bytes);
              void xed_decoded_inst_zero_set_mode(xed_decoded_inst_t* p,
                               const xed_state_t* dstate);
}
*/

// JVM TI agent return codes
const int ARGUMENTS_ERROR = 100;
const int COMMAND_ERROR = 200;

static Arguments _agent_args(true);

JavaVM* VM::_vm;
jvmtiEnv* VM::_jvmti = NULL;

int VM::_hotspot_version = 0;
bool VM::_openj9 = false;
bool VM::_can_sample_objects = false;

jvmtiError (JNICALL *VM::_orig_RedefineClasses)(jvmtiEnv*, jint, const jvmtiClassDefinition*);
jvmtiError (JNICALL *VM::_orig_RetransformClasses)(jvmtiEnv*, jint, const jclass* classes);

void* VM::_libjvm;
void* VM::_libjava;
AsyncGetCallTrace VM::__asyncGetCallTrace;
char method[100][1000];
void* method_pc[100];
int method_count = 0;

void _print_segv_info(void* ucontext) {
    const intptr_t MIN_VALID_PC = 0x1000;
const intptr_t MAX_WALK_SIZE = 0x100000;
const intptr_t MAX_FRAME_SIZE = 0x40000;
    const int max_depth = 1000;
    
    const void* pc;
    uintptr_t fp;
    uintptr_t prev_fp = (uintptr_t)&fp;
    uintptr_t bottom = prev_fp + MAX_WALK_SIZE;

    if (ucontext == NULL) {
        pc = __builtin_return_address(0);
        fp = (uintptr_t)__builtin_frame_address(1);
    } else {
        StackFrame frame(ucontext);
        pc = (const void*)frame.pc();
        fp = frame.fp();
    }

    int depth = 0;

    // Walk until the bottom of the stack or until the first Java frame
    while (depth < max_depth) {
         if (CodeHeap::contains(pc)) {
            break;
         }

        const char* current_method_name = Profiler::instance()->findNativeMethod(pc);
        if (method_count < 100) {
            strcpy(method[method_count], current_method_name);
            method_pc[method_count] = (void*)pc;
        }
        method_count++;
        break;
        if (current_method_name != NULL && NativeFunc::isMarked(current_method_name)) {
            // This is C++ interpreter frame, this and later frames should be reported
            // as Java frames returned by AGCT. Terminate the scan here.
            break;
        }
        //printf("%s\n", current_method_name);

        // Check if the next frame is below on the current stack
        if (fp <= prev_fp || fp >= prev_fp + MAX_FRAME_SIZE || fp >= bottom) {
            break;
        }

        // Frame pointer must be word aligned
        if ((fp & (sizeof(uintptr_t) - 1)) != 0) {
            break;
        }

        pc = stripPointer(SafeAccess::load((void**)fp + FRAME_PC_SLOT));
        if (pc < (const void*)MIN_VALID_PC || pc > (const void*)-MIN_VALID_PC) {
            break;
        }

        prev_fp = fp;
        fp = *(uintptr_t*)fp;
    }
}

int g_pid = -1;

void* segs[1000];
int segs_num;

/** parse into segs */
void pmparser2_parse(int pid, void* ucontext, ASGCT_CallTrace *trace){
	char maps_path[1000];
	if(pid>=0 ){
		sprintf(maps_path,"/proc/%d/maps",pid);
	}else{
		sprintf(maps_path,"/proc/self/maps");
	}
	std::ifstream file;
    file.open(maps_path);

	int ind=0;
    char buf[1000];
	int c;

	char addr_start_str[200], addr_end_str[200], perm_str[80], offset_str[200], dev_str[100], inode_str[300], pathname_str[1000];
	
	int i = 0;
    segs_num = 0;
    std::string line;
    while (std::getline(file, line) && i < max_procmap_entries) {
		memcpy(buf, line.c_str(), line.size() + 1);
		//printf("---> %s\n", buf);
		//allocate a node
		//fill the node
		_pmparser_split_line(buf, addr_start_str, addr_end_str, perm_str, offset_str, dev_str, inode_str, pathname_str);		//addr_start & addr_end
        unsigned long addr_start;
        sscanf(addr_start_str, "%lx", &addr_start);
        unsigned long addr_end;
		sscanf(addr_end_str, "%lx", &addr_end);
		//size
		unsigned long length = addr_end - addr_start;

        long offset;
		//offset
		sscanf(offset_str,"%lx", &offset);
		//inode
		int inode = atoi(inode_str);

		if (length == 0) {
			continue;
		}

		if (perm_str[0] == 'r') {
			//printf("%s\n", buf);
		}

        procmap_entry entry{
            (void*)addr_start,
            (void*)addr_end,
            length,
            perm_str[0] == 'r',
            perm_str[1] == 'w',
            perm_str[2] == 'x',
            perm_str[3] == 'p',
            strcmp(pathname_str, "[stack]") == 0,
            strcmp(pathname_str, "[heap]") == 0,
			strstr(pathname_str, "jdk") != 0,
			inode == 0,
			strstr(pathname_str, "lib/modules") != 0,
			inode
        };
        if (entry.is_x) {
            continue;
        }
            if ((size_t)entry.addr_start <= StackFrame(ucontext).sp() && (size_t)entry.addr_end >= StackFrame(ucontext).sp()) {
                continue;
            }
            if (entry.addr_start <= &method && &method < entry.addr_end) {
                continue;
            }
            if (entry.addr_start <= trace && trace < entry.addr_end) {
                continue;
            }
            if (entry.addr_start <= trace->frames && trace->frames < entry.addr_end) {
                continue;
            }
                if (entry.is_w && !entry.is_stack && (entry.is_java || entry.is_heap || entry.is_anon)) {
           //printf("%p - %p inode %d\n", entry.addr_start, entry.addr_end, entry.inode);
            
                    segs[segs_num] = (void*)addr_start;
        segs[segs_num + 1] = (void*)addr_end;
        segs_num += 2;
             //printf("+\n");
            //*((int*)entry.addr_start) = 10;
        }
        if (entry.is_stack) {
            auto len = (size_t)StackFrame(ucontext).sp() - 10000 - (size_t)entry.addr_start;
                    segs[segs_num] = (void*)addr_start;
        segs[segs_num + 1] = (void*)(addr_start + len);
        segs_num += 2;
        }
		i++;
	}
}


void _modify_protection(ASGCT_CallTrace *trace, void* ucontext, bool read_only) {
   for (int i = 0; i < segs_num; i += 2) {
        void* start = segs[i];
        void* end = segs[i + 1];
        mprotect(start, (size_t)end - (size_t)start, (read_only ? 0 : PROT_WRITE) | PROT_READ);
   }
    // handle the mapped_trace and mapped_frames: they have to be writable
    //mprotect(trace, sizeof(ASGCT_CallTrace), PROT_READ | PROT_WRITE);
    //mprotect(trace->frames, sizeof(ASGCT_CallFrame) * 1024, PROT_READ | PROT_WRITE);
}

void _asgct_segv_handle(int signo, siginfo_t* siginfo, void* ucontext) {
    void* addr = siginfo->si_addr;
    for (int i = 0; i < segs_num; i += 2) {
        void* start = segs[i];
        void* end = segs[i + 1];
        if (start <= addr && addr < end) {
            mprotect(start, (size_t)end - (size_t)start, PROT_READ | PROT_WRITE);
            //mprotect((void*)(((size_t)addr | 4048) - 4048), (size_t)end - (size_t)addr, PROT_READ | PROT_WRITE);
        }
    }
    //printf("sdf\n");
   
    //printf("after pro%p\n", frame.pc());
    _print_segv_info(ucontext);

//StackFrame frame(ucontext);

    // adapted from https://stackoverflow.com/a/44228587
   /* xed_bool_t long_mode = 1;
    xed_decoded_inst_t xedd;
    xed_state_t dstate;
    dstate.mmode=XED_MACHINE_MODE_LONG_64;
    mcontext_t* mcontext = &((ucontext_t*)ucontext)->uc_mcontext;
    uint8_t* code = (uint8_t*)mcontext->gregs[REG_RIP];
    unsigned char* itext = (unsigned char*)code;//frame.pc();*/
    //xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    //xed_ild_decode(&xedd, itext, XED_MAX_INSTRUCTION_BYTES);
    //frame.pc() += xedd._decoded_length;
    //mcontext->gregs[REG_RIP] += xedd._decoded_length;
    //printf("length = %u\n", xedd._decoded_length);

    //StackFrame(ucontext).pc() += 2;
    //raise(SIGABRT);
    //exit(0);
}

ASGCT_CallTrace* g_trace;
jint g_depth;


void _asgct_child(const procmap_array &entries, int num, 
    ASGCT_CallTrace *trace, jint depth, void* ucontext, int socket) {
    OS::replaceCrashHandler(_asgct_segv_handle);
        int s[100000];
    pmparser2_parse(g_pid, ucontext, trace);
    _modify_protection(trace, ucontext, true);
    //printf("%d\n", __LINE__);
    trace->env = VM::jni();
    //getcontext((ucontext_t*)ucontext);
    VM::__asyncGetCallTrace(trace, depth, ucontext);

    _modify_protection(trace, ucontext, false);
    for (int i = 0; i < method_count; i++) {
        printf("%s\n", method[i]);
        void* pc = method_pc[i];
        /*CodeCache* nl = Profiler::instance()->findNativeLibrary(pc);
        printf("%s\n", nl->name());
        char buf[1000];
        sprintf(buf, "addr2line -f -e %s %p", nl->name(), pc);
        printf("command: %s\n", buf);
        system(buf);*/
    }
    //exit(0);
}

int in_child = 0;

void VM::_asyncGetCallTrace(ASGCT_CallTrace* trace, jint depth, void* ucontext) {
    if (g_pid == -1) {
        g_pid = getpid();
    }
    if (in_child > 3) {
        return;
    }
    procmap_array entries;
    //int num = pmparser_parse(g_pid, entries);

    int status;
    trace->num_frames = -10;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        exit(1);
    }
    pid_t pid = fork();
    if (pid == 0) { // child process
        in_child++;
        _asgct_child(entries, 1, trace, depth, ucontext, sv[0]);
    } else { // parent process
        int socket = sv[1];
        char buf;
        //read(socket, &buf, 1); // wait for the signal handler to be registered
        //usleep(1); // sleep so that the fork can escape from the signal handler
        //kill(pid, SIGUSR1);
        //waitpid(pid, &status, 0);
        trace->num_frames = 0;
    }
}

JVM_GetManagement VM::_getManagement;


static void wakeupHandler(int signo) {
    // Dummy handler for interrupting syscalls
}

static bool isZeroInterpreterMethod(const char* blob_name) {
    return strncmp(blob_name, "_ZN15ZeroInterpreter", 20) == 0
        || strncmp(blob_name, "_ZN19BytecodeInterpreter3run", 28) == 0;
}

static bool isOpenJ9InterpreterMethod(const char* blob_name) {
    return strncmp(blob_name, "_ZN32VM_BytecodeInterpreter", 27) == 0
        || strncmp(blob_name, "_ZN26VM_BytecodeInterpreter", 27) == 0
        || strncmp(blob_name, "bytecodeLoop", 12) == 0
        || strcmp(blob_name, "cInterpreter") == 0;
}

static bool isOpenJ9JitStub(const char* blob_name) {
    if (strncmp(blob_name, "jit", 3) == 0) {
        blob_name += 3;
        return strcmp(blob_name, "NewObject") == 0
            || strcmp(blob_name, "NewArray") == 0
            || strcmp(blob_name, "ANewArray") == 0;
    }
    return false;
}


bool VM::init(JavaVM* vm, bool attach) {
    //xed_tables_init();

    if (_jvmti != NULL) return true;

    _vm = vm;
    if (_vm->GetEnv((void**)&_jvmti, JVMTI_VERSION_1_0) != 0) {
        return false;
    }

#ifdef __APPLE__
    Dl_info dl_info;
    if (dladdr((const void*)wakeupHandler, &dl_info) && dl_info.dli_fname != NULL) {
        // Make sure async-profiler DSO cannot be unloaded, since it contains JVM callbacks.
        // On Linux, we use 'nodelete' linker option.
        dlopen(dl_info.dli_fname, RTLD_LAZY | RTLD_NODELETE);
    }
#endif

    bool is_hotspot = false;
    bool is_zero_vm = false;
    char* prop;
    if (_jvmti->GetSystemProperty("java.vm.name", &prop) == 0) {
        is_hotspot = strstr(prop, "OpenJDK") != NULL ||
                     strstr(prop, "HotSpot") != NULL ||
                     strstr(prop, "GraalVM") != NULL ||
                     strstr(prop, "Dynamic Code Evolution") != NULL;
        is_zero_vm = strstr(prop, "Zero") != NULL;
        _jvmti->Deallocate((unsigned char*)prop);
    }

    if (is_hotspot && _jvmti->GetSystemProperty("java.vm.version", &prop) == 0) {
        if (strncmp(prop, "25.", 3) == 0) {
            _hotspot_version = 8;
        } else if (strncmp(prop, "24.", 3) == 0) {
            _hotspot_version = 7;
        } else if (strncmp(prop, "20.", 3) == 0) {
            _hotspot_version = 6;
        } else if ((_hotspot_version = atoi(prop)) < 9) {
            _hotspot_version = 9;
        }
        _jvmti->Deallocate((unsigned char*)prop);
    }

    _libjvm = getLibraryHandle("libjvm.so");
    __asyncGetCallTrace = (AsyncGetCallTrace)dlsym(_libjvm, "AsyncGetCallTrace");
    _getManagement = (JVM_GetManagement)dlsym(_libjvm, "JVM_GetManagement");

    Profiler* profiler = Profiler::instance();
    profiler->updateSymbols(false);

    _openj9 = !is_hotspot && J9Ext::initialize(_jvmti, profiler->resolveSymbol("j9thread_self"));
    _can_sample_objects = !is_hotspot || hotspot_version() >= 11;

    CodeCache* lib = isOpenJ9()
        ? profiler->findJvmLibrary("libj9vm")
        : profiler->findNativeLibrary((const void*)__asyncGetCallTrace);
    if (lib == NULL) {
        return false;  // TODO: verify
    }

    VMStructs::init(lib);
    if (is_zero_vm) {
        lib->mark(isZeroInterpreterMethod);
    } else if (isOpenJ9()) {
        lib->mark(isOpenJ9InterpreterMethod);
        CodeCache* libjit = profiler->findJvmLibrary("libj9jit");
        if (libjit != NULL) {
            libjit->mark(isOpenJ9JitStub);
        }
    }

    if (attach) {
        ready();
    }

    jvmtiCapabilities capabilities = {0};
    capabilities.can_generate_all_class_hook_events = 1;
    capabilities.can_retransform_classes = 1;
    capabilities.can_retransform_any_class = isOpenJ9() ? 0 : 1;
    capabilities.can_generate_vm_object_alloc_events = isOpenJ9() ? 1 : 0;
    capabilities.can_generate_sampled_object_alloc_events = _can_sample_objects ? 1 : 0;
    capabilities.can_get_bytecodes = 1;
    capabilities.can_get_constant_pool = 1;
    capabilities.can_get_source_file_name = 1;
    capabilities.can_get_line_numbers = 1;
    capabilities.can_generate_compiled_method_load_events = 1;
    capabilities.can_generate_monitor_events = 1;
    capabilities.can_tag_objects = 1;
    if (_jvmti->AddCapabilities(&capabilities) != 0) {
        _can_sample_objects = false;
        capabilities.can_generate_sampled_object_alloc_events = 0;
        _jvmti->AddCapabilities(&capabilities);
    }

    jvmtiEventCallbacks callbacks = {0};
    callbacks.VMInit = VMInit;
    callbacks.VMDeath = VMDeath;
    callbacks.ClassLoad = ClassLoad;
    callbacks.ClassPrepare = ClassPrepare;
    callbacks.ClassFileLoadHook = Instrument::ClassFileLoadHook;
    callbacks.CompiledMethodLoad = Profiler::CompiledMethodLoad;
    callbacks.DynamicCodeGenerated = Profiler::DynamicCodeGenerated;
    callbacks.ThreadStart = Profiler::ThreadStart;
    callbacks.ThreadEnd = Profiler::ThreadEnd;
    callbacks.MonitorContendedEnter = LockTracer::MonitorContendedEnter;
    callbacks.MonitorContendedEntered = LockTracer::MonitorContendedEntered;
    callbacks.VMObjectAlloc = J9ObjectSampler::VMObjectAlloc;
    callbacks.SampledObjectAlloc = ObjectSampler::SampledObjectAlloc;
    _jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));

    _jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH, NULL);
    _jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_LOAD, NULL);
    _jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, NULL);
    _jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, NULL);

    if (hotspot_version() == 0 || !CodeHeap::available()) {
        // Workaround for JDK-8173361: avoid CompiledMethodLoad events when possible
        _jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL);
    } else {
        // DebugNonSafepoints is automatically enabled with CompiledMethodLoad,
        // otherwise we set the flag manually
        char* flag_addr = (char*)JVMFlag::find("DebugNonSafepoints");
        if (flag_addr != NULL) {
            *flag_addr = 1;
        }
    }

    if (attach) {
        loadAllMethodIDs(jvmti(), jni());
        _jvmti->GenerateEvents(JVMTI_EVENT_DYNAMIC_CODE_GENERATED);
        _jvmti->GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD);
    } else {
        _jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
    }

    OS::installSignalHandler(WAKEUP_SIGNAL, NULL, wakeupHandler);

    return true;
}

// Run late initialization when JVM is ready
void VM::ready() {
    {
        JitWriteProtection jit(true);
        VMStructs::ready();
    }

    Profiler::setupSignalHandlers();

    _libjava = getLibraryHandle("libjava.so");

    // Make sure we reload method IDs upon class retransformation
    JVMTIFunctions* functions = *(JVMTIFunctions**)_jvmti;
    _orig_RedefineClasses = functions->RedefineClasses;
    _orig_RetransformClasses = functions->RetransformClasses;
    functions->RedefineClasses = RedefineClassesHook;
    functions->RetransformClasses = RetransformClassesHook;
}

void* VM::getLibraryHandle(const char* name) {
    if (!OS::isJavaLibraryVisible()) {
        void* handle = dlopen(name, RTLD_LAZY);
        if (handle != NULL) {
            return handle;
        }
        Log::warn("Failed to load %s: %s", name, dlerror());
    }
    return RTLD_DEFAULT;
}

void VM::loadMethodIDs(jvmtiEnv* jvmti, JNIEnv* jni, jclass klass) {
    if (VMStructs::hasClassLoaderData()) {
        VMKlass* vmklass = VMKlass::fromJavaClass(jni, klass);
        int method_count = vmklass->methodCount();
        if (method_count > 0) {
            ClassLoaderData* cld = vmklass->classLoaderData();
            cld->lock();
            // Workaround for JVM bug: preallocate space for jmethodIDs
            // at the beginning of the list (rather than at the end)
            for (int i = 0; i < method_count; i += MethodList::SIZE) {
                *cld->methodList() = new MethodList(*cld->methodList());
            }
            cld->unlock();
        }
    }

    jint method_count;
    jmethodID* methods;
    if (jvmti->GetClassMethods(klass, &method_count, &methods) == 0) {
        jvmti->Deallocate((unsigned char*)methods);
    }
}

void VM::loadAllMethodIDs(jvmtiEnv* jvmti, JNIEnv* jni) {
    jint class_count;
    jclass* classes;
    if (jvmti->GetLoadedClasses(&class_count, &classes) == 0) {
        for (int i = 0; i < class_count; i++) {
            loadMethodIDs(jvmti, jni, classes[i]);
        }
        jvmti->Deallocate((unsigned char*)classes);
    }
}

void VM::restartProfiler() {
    Profiler::instance()->restart(_agent_args);
}

void JNICALL VM::VMInit(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    ready();
    loadAllMethodIDs(jvmti, jni);

    // Delayed start of profiler if agent has been loaded at VM bootstrap
    Error error = Profiler::instance()->run(_agent_args);
    if (error) {
        Log::error("%s", error.message());
    }
}

void JNICALL VM::VMDeath(jvmtiEnv* jvmti, JNIEnv* jni) {
    Profiler::instance()->shutdown(_agent_args);
}

jvmtiError VM::RedefineClassesHook(jvmtiEnv* jvmti, jint class_count, const jvmtiClassDefinition* class_definitions) {
    jvmtiError result = _orig_RedefineClasses(jvmti, class_count, class_definitions);

    if (result == 0) {
        // jmethodIDs are invalidated after RedefineClasses
        JNIEnv* env = jni();
        for (int i = 0; i < class_count; i++) {
            if (class_definitions[i].klass != NULL) {
                loadMethodIDs(jvmti, env, class_definitions[i].klass);
            }
        }
    }

    return result;
}

jvmtiError VM::RetransformClassesHook(jvmtiEnv* jvmti, jint class_count, const jclass* classes) {
    jvmtiError result = _orig_RetransformClasses(jvmti, class_count, classes);

    if (result == 0) {
        // jmethodIDs are invalidated after RetransformClasses
        JNIEnv* env = jni();
        for (int i = 0; i < class_count; i++) {
            if (classes[i] != NULL) {
                loadMethodIDs(jvmti, env, classes[i]);
            }
        }
    }

    return result;
}


extern "C" DLLEXPORT jint JNICALL
Agent_OnLoad(JavaVM* vm, char* options, void* reserved) {
    Error error = _agent_args.parse(options);

    Log::open(_agent_args._log, _agent_args._loglevel);
    if (_agent_args._unknown_arg != NULL) {
        Log::warn("Unknown argument: %s", _agent_args._unknown_arg);
    }

    if (error) {
        Log::error("%s", error.message());
        return ARGUMENTS_ERROR;
    }

    if (!VM::init(vm, false)) {
        Log::error("JVM does not support Tool Interface");
        return COMMAND_ERROR;
    }

    return 0;
}

extern "C" DLLEXPORT jint JNICALL
Agent_OnAttach(JavaVM* vm, char* options, void* reserved) {
    Arguments args(true);
    Error error = args.parse(options);

    Log::open(args._log, args._loglevel);
    if (args._unknown_arg != NULL) {
        Log::warn("Unknown argument: %s", args._unknown_arg);
    }

    if (error) {
        Log::error("%s", error.message());
        return ARGUMENTS_ERROR;
    }

    if (!VM::init(vm, true)) {
        Log::error("JVM does not support Tool Interface");
        return COMMAND_ERROR;
    }

    // Save the arguments in case of shutdown
    if (args._action == ACTION_START || args._action == ACTION_RESUME) {
        _agent_args.save(args);
    }

    error = Profiler::instance()->run(args);
    if (error) {
        Log::error("%s", error.message());
        return COMMAND_ERROR;
    }

    return 0;
}

extern "C" DLLEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    if (!VM::init(vm, true)) {
        return 0;
    }

    JavaAPI::registerNatives(VM::jvmti(), VM::jni());
    return JNI_VERSION_1_6;
}

extern "C" DLLEXPORT void JNICALL
JNI_OnUnload(JavaVM* vm, void* reserved) {
    Profiler* profiler = Profiler::instance();
    if (profiler != NULL) {
        profiler->stop();
    }
}
