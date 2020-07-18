using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;

namespace PasswordHashing
{
    public static class Program
    {
        private const int _saltSize = 128 / 8;
        private const int _hashSize = 256 / 8;
        private const int _iterationCount = 10000;

        static void Main(string[] args)
        {
            Console.WriteLine("Enter a password: ");
            string password = Console.ReadLine();

            var salt = new byte[_saltSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            var hash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: _iterationCount,
                numBytesRequested: _hashSize
            );

            Console.WriteLine($"Hash: {Convert.ToBase64String(hash)}");
            Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");
        }
    }
}
