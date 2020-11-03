using CrossPlatformDSA.DSA.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class WindowsLib : ILibrary
    {
        KalkanCryptCOMLib.KalkanCryptCOM _kalkan;
        private int kalkanFlag;

        public WindowsLib()
        {
            _kalkan = new KalkanCryptCOMLib.KalkanCryptCOM();
            _kalkan.Init();
        }
        public bool VerifyData(byte[] data)
        {
            bool res = false;
            string base64Str,outData,outVerifyInfo,outCert,errStr;
            uint err;
            int dsf=34;
           base64Str= Convert.ToBase64String(data);
            int df = base64Str.Length;
            string data2 = "XILmrm0t7MlkY/K6yLb10s+7nRLHli6IN9OGth/oaKc=";
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            _kalkan.VerifyData("", kalkanFlag, 1, "", base64Str, out outData, out outVerifyInfo, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);
            if(err==0)
            {
                res = true;
            }
            return res;
        }
    }
}
