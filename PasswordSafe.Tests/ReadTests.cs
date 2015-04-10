using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PasswordSafe.Crypto;
using PasswordSafeCrypto = PasswordSafe.Net.Crypto.PasswordSafeCrypto;

namespace PasswordSafe.Tests
{
    [TestClass]
    public class ReadTests
    {
        private const string TestPsafe3 = "../../../test.psafe3"; //assuming working copy from top-level or repo, working back from PasswordSafe.Net/PasswordSafe.Tests/bin/debug
        private const string CopyPsafe3 = "../../../pwsafe - Copy.psafe3"; //assuming working copy from top-level or repo, working back from PasswordSafe.Net/PasswordSafe.Tests/bin/debug

        private const string TestSafePassword = "test123";

        [TestMethod]
        public void ReadTestSafe()
        {
            using (var stream = File.Open(TestPsafe3, FileMode.Open, FileAccess.Read))
            {
                var safe = Safe.Load(new PasswordSafeCrypto(), stream, TestSafePassword);
                Assert.AreEqual(1, safe.Items.Count);
            }
        }

        private static DateTime GetPsafe3ComparableDateTime(DateTime dt)
        {
            return new DateTime(
                    dt.Year,
                    dt.Month,
                    dt.Day,
                    dt.Hour,
                    dt.Minute,
                    dt.Second,
                    dt.Kind
                );
        }

        [TestMethod]
        public void WriteTestSafe()
        {
            var createdDate = GetPsafe3ComparableDateTime(DateTime.Now);
            var safe = NewTestSafe(createdDate);
            //truncated or otherwise corrupt
            using (var fs = File.Open(TestPsafe3, FileMode.Create))
                safe.Save(fs, TestSafePassword);
            using (var fs = File.Open(TestPsafe3, FileMode.Open))
                safe = Safe.Load(new PasswordSafeCrypto(), fs, TestSafePassword);
            Assert.AreEqual(1, safe.Items.Count);
            var firstItem = safe.Items[0];
            Assert.AreEqual("My first entry", firstItem.Title);
            Assert.AreEqual(createdDate, firstItem.CreatedTime);
            Assert.AreEqual("abc123", firstItem.Password);
        }

        [TestMethod]
        public void ReadBlankSafe()
        {
            var crypto = (IPasswordSafeCrypto) new PasswordSafeCrypto();
            Safe safe;
            using (var fs = File.Open(CopyPsafe3, FileMode.Open))
                safe = Safe.Load(crypto, fs, TestSafePassword);
        }

        private static Safe NewTestSafe(DateTime createdDate)
        {
            if (createdDate.Millisecond != 0)
            {
                throw new ArgumentOutOfRangeException("createdDate", "psafe3 format does not support resolution below seconds");
            }

            var crypto = (IPasswordSafeCrypto)new PasswordSafeCrypto();
            var safe = new Safe(crypto);

            safe.LastUpdateHost = "GRIFFIN";
            safe.LastUpdateTime = createdDate;
            safe.LastUpdateUser = "pengt";
            safe.NonDefaultUserPrefs = "";
            safe.Uuid = Guid.NewGuid();
            safe.Version = new Version(3, 9);
            safe.LastUpdateApplication = "Password Safe V3.27";

            var item = new Item
            {
                Uuid = Guid.NewGuid(),
                CreatedTime = createdDate,
                Title = "My first entry",
                Password = "abc123"
            };
            safe.Items.Add(item);
            return safe;
        }

        [TestMethod]
        public void RoundTripUnencrypted()
        {
            var createdDate = GetPsafe3ComparableDateTime(DateTime.Now);
            var safe = NewTestSafe(createdDate);
            using (var ms = new MemoryStream())
            {
                safe.SaveUnencrypted(ms);
                ms.Position = 0;
                var restoredSafe = Safe.LoadUnencrypted(ms);
                Assert.AreEqual(safe.Items.Count, restoredSafe.Items.Count);
            }
        }
    }
}
