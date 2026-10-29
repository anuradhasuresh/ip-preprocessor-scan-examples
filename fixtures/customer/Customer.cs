// Deliberately synthetic customer code. No ownership claim is made.
using Microsoft.Win32;

namespace SyntheticCustomer;

public static class Customer
{
    public const string Documentation = "https://learn.microsoft.com/dotnet/";
    public const string PackageName = "Microsoft.Extensions.Logging";

    public static decimal OrderTotal(decimal price, int quantity) => price * quantity;
}
