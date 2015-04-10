namespace PasswordSafe.Crypto
{
    public interface IHMACSHA256Factory
    {
        IKeyedHashAlgorithm From(byte[] bytes);
    }
}