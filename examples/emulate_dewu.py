import logging
import os
import urllib.request
from pathlib import Path

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC, pyobj2nsobj

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger()


def download_sample_file(binary_path: str) -> str:
    filepath = os.path.join(base_path, "..", binary_path)

    path = Path(filepath).resolve()
    if path.exists():
        return filepath

    if not path.parent.exists():
        path.parent.mkdir(parents=True)

    url = "https://sourceforge.net/projects/chomper-emu/files/%s/download" % binary_path
    print(f"Downloading sample file: {url}")
    urllib.request.urlretrieve(url, path)

    return filepath


def main():
    binary_path = "examples/binaries/ios/com.siwuai.duapp/5.61.4/DUApp"

    # Download sample file from SourceForge
    download_sample_file(binary_path)
    download_sample_file(f"{binary_path}/../Info.plist")

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
        enable_ui_kit=True,
    )
    objc = ObjC(emu)

    emu.load_module(os.path.join(base_path, "..", binary_path))

    with objc.autorelease_pool():
        # Decrypt
        headers = pyobj2nsobj(emu, {
            "sks": "2,1,0",
            "Content-Type": "application/json;charset=UTF-8",
        })
        data = pyobj2nsobj(emu, b'{"code": 200,"data": "A3El6CecquxeBgFfJp6x_tKc1zVwCWWkH0UTXyaXo-27jC1_2U_nzggUCwgmnq39TletamG4gewYWlRRPtElIo7RMypAbgcKy74TXyafq-oSY1TcqMAlfht9VAomyeCqumtCsGCdb4leBgFDV6OXtJ74awXPXPNYXAYBQzTe-6BYmxA64jWhjV8BAUE9x_GpVGOrgZbXdftAFEIDcbqmu2004a9i_OXuWxoTB22Hrvxwvtn2UVu9Yd0W1siLFkchnGB_P5aHzZPxBAWWoFQnFeIwr2Y3ltOh1o7UxLoVSCSOYEJTjWml5cTTn-3icGJxh0TR-QVTSxyFkqGWs00lI72GG4aKXYEnw47U_q8UVgYFMP4Xnu98Df3frNHhRHy7OxV9MQ98ZLNWDwFDKNGu9jeAYGrEtjVuBEJFA3fJ7baMZguGC2ITEQNYHxBrnu3pTshTK2Y3UM8eX1Yaat6r9Ce570Nr1dudXA4eEmfKofzfFA5ly6XdNFgCVxIykKOsAACEhQl9gJFfVFJdboOluw-5BzK576TDARQLQjTD8KqVozD5MxCnmAl4UB5h0fi70vkfySKTJqQfG14VcJasu4fsLCH7VZtZVgYdUW2Ajf-ThHzndnPBqRlYRRZ20fitAnuXZt3rFysPQhNJJpu27TIw4dJtty4zCUFEXWecr7bRKmw-Nfbvnx5ZVQZnh-3Jb-MggsYgs1cYV1gfO4Cy7B1aN07b6d-7VAcGVXect-vjjDIASPwIpgNZRR5lganqrX_VbJgKwb0VYFAfcZaL_bD2-6-kQEFzWgQXAG-Gi_3HW95e-4IPxFUGFxdhh6PwQgdk-sLS_71JAXNWNsGn4WajbZMgjflsH2BQHyHB8LwtvLXFxzfcCl4TAzAhwfD8asE_HHfSeJc6V11WNsHnqt4gg7VujYf7SQRyVjbBp-G9Fbgkv3IbmjpXXVY2weeq0RCS0FmUD21JBHJWNsGn4b0VuCS_chuaJFNYFGyH56vaMcPHJiG5AUIAAkUhwfC8b7x-CzGW2r8_QkgfYae76Ru3HzHfKdohXgQAVjbB565STWNSiaiQJwlERQpSkq7srPPkb-PNAtdUBghDMsHuuw3mpNADBjY3XQ4CRzTK-6nqSqLhgushjjhEUBBtnaXdHeZ9qqicyRVATRMBa4SJ_APfNbNjZnVCXw4DQTHB8qlwG-HRnstQXFwGAUM0w_KpSkxVLZZyKbJBDwNBN8D1qaWxJ2IdugJHXwYBQCbf4OpSGax4iYKMhVgAA0c1we678N2msCTz2cSKipqbjkLifPKjCIxr1p-KXQYBQ-FPYqiNcCp5fEn7C-CzEZWGXyQVwvfigRxjLbzWjtTEutP2fOzuUgD5IdIWThoTA3aaofzNo_qVJziCbwBZVhxRga67BM9Ry-jiea1DGVIXat2y9lvahqiOpwOlQ0ZDHCmar_506ahYxsBVmgVbVlw2w_CtDBp_9mkeOwpbBwVGZpXz-MZpkqqhwCmUDlBUQGCV8Ph56t-7Mxt6VQsUHVF3nK79aNHI4yd1fXVaAh1Rd5y360gTkVRgyjXuTlBeHHCeo-uCIeAIszD7K04aExp3t6f12rq3uOSMpBkKUBNJNN_g-pA7aDU0Ma67XRoTAWGXq-sdsh6mV0a1sRhGQkkr3K-3nLS9vp59bJZDRF4GcJawtsAVE85aLqigPEReF3GQtt1bj3PAMDwefRl_VU41x_avPAAskKxRHeQeVVQ9ZZ6npNL5H8kikyakHxBBAWuDp-sZViAuo_mIDAgLBUsxy_Oq_hmlK80hA2wICwZCPMD2rWPSVZcX8rs7BVp0C3C-o-nfPHXL5gOqBhRCeB5jp7D4VR6FTw0UcShJBXBWNsHzvCThnQokPcvTCU5FOmmUlvbnTp65O29HoF93FEE2w-erFLMxdneGfJ4UQngeY7et7rYB4gRejkOgX3cUQTbC56sUszF2d4Z8nhRCeB5jt63u819cef613npeBBRARdbwq_HTdVCu0tlESQRyVjbBq_Q4bVTX4mK6WhxTFEE21vHYilV38-Rjcq5bchNfJoOw9o5NixAvPGWsGVN4FybJ9qFyxgrm1v5F_k5FWgZNl-CjGfNobMgC-j1cGhMQa56v9o2O1_7BsSu9KFdFEibJueT1I7t5tSkv1xgUCyh_0ab4AjqcDEC3vA9UAAVDNN_g9RZOArz2d5yfHllGOGGK4KPODRWF-cn-Sl4DA0M0w5HJBGKqv2rr0FRcBAhHN8P1r4qWWHlLbSiAH0ZEOmDR-Khd6cbQCCM1DU5CWAdoluCjSjiGSVYUEviLjb6WgUsnNAu-Yf5L9y9YWNOV1OF_R3_h0k48jep7Q4mBj5WOTiUjQzuuFHicuSPCqNfwpBthHNiPHwR6Zs7d_NOGzeNJenwm1o6uIISqWYm7mpSQbCUjHeiU9ICmQxHxlNTEutHuu8qHb_4wSNKkXAYdUWicpfayj6fkXYt4LhhGQkkr3KH9aFd1HIOs6WJCVV4eK4Ow9meDoL3K2063C19fXm2epbasaCc3x54rmENXUkpnlvT4J_KKqHbDWYsKVwcQZcagqTJ9cfBgI-IWDxhbA2PR7ruWbUCL78IoN1YHAUM2wPq1jID_edsx3VgNW1RRPtGk9n_VdGlFyDqGQBRYAECWrrtfk1dEX0CpZgoUC0Mo0bbw_W42AdeCqtsYX1wWJsnzrnhzSPbowhIJVQQCXyaDsPaOTYsQLzxlrBlTeBcmyfahpFYXaMg64EhORFQXbYGn-iFmwxhDz2dAHwweXGndpvxlFVeenxvYLANDRRZ23LLrHWYrdyIq0rMDUkQQcLen7VH18sCjxHhYCAsARzHL8qGZGvSdqr1G3Ql4UB5hzqT2YKJ6jcV-kzkcRF4DYYG24ITAF7OB3pu3WA4ESzTK8q9rRmUkPY4iKlsHCUAww_ugdhMOxMwjMWYpTkU-ZYP_vHJJna8LziNXJVtWJ3aSrOp9Ddt7isGLqi0TA0E11vCrYe2B8dpMHAoYf1wUUJyyzyNb54b-g3sZSQQDQyHB8Lxm3xvAerHwhSVbVjdrhKzPI1vnhv6DexlJBANCIcHwvGbfG8B6sfCFJVtWN2uErNFt11OOcZZozUkFcFY2wfK3fzZSQv5Gdv0vEwNBbZ6lypnTtDNJOICTSQQDVjey56sx1Z0iENqzKk4aEwBvhov9jDShr3Xz8UxVDwFfJpCt9A5sCkTKXm8FAlF1EnCS4KNv5h9wDa0I2Rt9VAomyeCqumtCsGCdb4leBgFDV6OXtA5OD9Sme8bqVQICQjbD9qp6YJrlnVzU1Bl_VVE-wvat8f8n2pEWEBMFQl0WJsngf9nk-R0l1qZ5496q3eN1SKjkeiLcNzPBw4q5oZagVCcVI6UEujWdo-WJir6Vjk4lIwQX61tvM0-K7tOA8eJmcrs7FX0xD3xks1YHAUM03-D1MZHSPl9oGO9OXkUHdID4tswmlWfVwlRVFllfXWecr7Y7zd4tcwt8uwNEWBRtne_wOE1cLK2srRJUBglcZ5GkrhQfaLWfuwvLWFAEFj3L9fsf-rLFZ9pRH1pTUBYqmbL-BqTZeyQki3QZWxNJM8fxr_AFjKXyyY0qCXhQHmHR-LvS-R_JIpMmpB8UHVFtgIb8klOEAHForigjUFdRPsPuuzWJO-3r0ycKQBRFGmmW4KPi7faQgWrpUV8ECUMw3-DpMLoK3NGvTqcNWkQWTZfgo5mT5j_AQ7acXxoTAWGXq-sdsh6mV0a1sRhGQkkr3K-3nLS9vp59bJZDRF4GcJawtsAVE85aLqigPEReF3GQtt1bj3PAMDwefRl_VU41x_avPAAskKxRHeQeVVQ9ZZ6npNL5H8kikyakHxBBAWuDp-sZViAuo_mIDAgLBUsxy_Oq_hmlK80hA2wICwZCPMD2rWPSVZcX8rs7BVp0C3C-o-nfPHXL5gOqBhRCeB5jp7D4VR6FTw0UcShJBXBWNsHzvCThnQokPcvTCU5FOmmUlvbnTp65O29HoF93FEE2w-erFLMxdneGfJ4UQngeY7et7rYB4gRejkOgX3cUQTbC56sUszF2d4Z8nhRCeB5jt63u819cef613npeBBRARdbwq_HTdVCu0tlESQRyVjbBq_Q4bVTX4mK6WhxTFEE21vHYilV38-Rjcq5bchNfJoCp7Js22M5AhLvZWAIBSjTf4PrPXuybmiRQtg9fXxRAkrb4C7DtnJjBputAFF0Sd4eL_Sd0vd3HtWwtVAQDRjbD8qnblDT0OjooaF8BAUE9x_Goy9teGPwfs04RGhMAcJK27BUTsooxQVQxbDYxcwTzwplYUXlHc_MEMQ==","status": 200}')
        path = pyobj2nsobj(emu, "/api/v1/app/index/ice/flow/product/detailV5")

        decrypt_result = objc.msg_send("DuSanwaSDK", "duSecDouDecodeWithHeader:origionData:path:", headers, data, path)
        decrypt_result_str = emu.read_string(objc.msg_send(decrypt_result, "bytes"))

        logger.info("Decrypt result: %s", decrypt_result_str)


if __name__ == "__main__":
    main()
