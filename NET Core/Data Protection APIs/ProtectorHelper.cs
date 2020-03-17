public class ProtectorHelper {
		private readonly IDataProtector protector;

		public ProtectorHelper(IDataProtectionProvider protectionProvider, IConfiguration configuration) {
			protector = protectionProvider.CreateProtector(configuration["your:secretKey"]);
		}
		public byte[] Encrypt(byte[] array, TimeSpan time) {
			var protectorTimeLimit = protector.ToTimeLimitedDataProtector();
			return protectorTimeLimit.Protect(array, time);
		}
		public byte[] Decrypt(byte[] array, out DateTimeOffset time) {
			var protectorTimeLimit = protector.ToTimeLimitedDataProtector();
			return protectorTimeLimit.Unprotect(array,out time);
		}
		public string Encrypt(string str, TimeSpan time) {
			var protectorTimeLimit = protector.ToTimeLimitedDataProtector();
			return protectorTimeLimit.Protect(str, time);
		}
		public string Decrypt(string str, out DateTimeOffset time) {
			var protectorTimeLimit = protector.ToTimeLimitedDataProtector();
			return protectorTimeLimit.Unprotect(str, out time);
		}

		public string Encrypt(string str) => protector.Protect(str);

		public string Decrypt(string str) => protector.Unprotect(str);

		public byte[] Encrypt(byte[] array) => protector.Protect(array);

		public byte[] Decrypt(byte[] array) => protector.Unprotect(array);
	}
