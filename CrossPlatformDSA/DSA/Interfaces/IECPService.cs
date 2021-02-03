using CrossPlatformDSA.DSA.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Interfaces
{
	public interface IECPService
	{
		bool VerifyData(byte[] cms, UserCertInfo userCertInfo);

		byte[] GetFile(byte[] cms);
		UserCertInfo GetInfo(byte[] cms);
	}
}
