import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))

rootfs_path = os.path.join(base_path, "../../rootfs/ios")
module_path = os.path.join(base_path, "../../examples/binaries/ios/com.jiangjia.gif/gifCommonFramework")


def hook_ksecurity_perf_report_sg_perf_report(uc, address, size, user_data):
    pass


def main():
    if not os.path.exists(module_path):
        print(
            "Binary doesn't exist, please download "
            "from 'https://sourceforge.net/projects/chomper-emu/files/'"
        )
        return

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=rootfs_path,
    )
    objc = ObjcRuntime(emu)

    emu.load_module(module_path)

    guard_manager_class = objc.find_class("KWOpenSecurityGuardManager")
    guard_param_context_class = objc.find_class("KWOpenSecurityGuardParamContext")
    signature_component_class = objc.find_class("KWOpenSecureSignatureComponent")
    perf_report_class = objc.find_class("KSecurityPerfReport")

    # Auth file
    auth_file = "video_yh_loading_icon.kss"

    # Forward file accesses
    emu.os.forward_path(
        f"{os.path.dirname(emu.os.executable_path)}/{auth_file}",
        os.path.join(module_path, "..", auth_file)
    )

    # Diable data report
    emu.add_interceptor(
        perf_report_class.get_instance_method("sgPerfReport:message:errorCode:").implementation,
        hook_ksecurity_perf_report_sg_perf_report,
    )

    with objc.autorelease_pool():
        # Initialize
        manager = guard_manager_class.call_method("getInstance")
        manager.call_method("initSDK")
        manager.call_method("setIsInitialize:", 1)

        component = signature_component_class.call_method("alloc")
        component.call_method("init")

        # Sign
        app_key = objc.create_ns_string("d7b7d042-d4f2-4012-be60-d97ff2429c17")
        input_str = objc.create_ns_data(b"test")
        wbindex_key = objc.create_ns_string("lD6We1E8i")
        sdk_id = objc.create_ns_string("")
        sdk_name = objc.create_ns_string("")
        ztconfig_file_path = objc.create_ns_string("")

        context = guard_param_context_class.call_method(
            "createParamContextWithAppKey:paramDict:requestType:input:wbindexKey:bInnerInvoke:sdkid:sdkName:ztconfigFilePath:",
            app_key,
            0,
            1,
            input_str,
            wbindex_key,
            0,
            sdk_id,
            sdk_name,
            ztconfig_file_path,
        )

        component.call_method("atlasSignPlus:", context)

        output = context.call_method("output")
        data_bytes = output.call_method("bytes")
        data_length = output.call_method("length")

        result = emu.read_bytes(data_bytes, data_length).decode("utf-8")
        emu.logger.info("Result: %s", result)


if __name__ == "__main__":
    main()
