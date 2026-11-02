// Deliberately synthetic customer code. No ownership claim is made.
// Fixture: customer - clean control.
// Expected for the customer-only scenario: Continue (RunHyenas / ContinueMDASH).
// References to Microsoft technology are not ownership declarations.

// Importing an API namespace does not claim authorship of this file.
using Microsoft.Win32;

namespace SyntheticCustomer;

public static class Customer
{
    // A documentation link, not an ownership statement.
    public const string Documentation = "https://learn.microsoft.com/dotnet/";

    // A package-name string, not an actual dependency or an ownership statement.
    public const string PackageName = "Microsoft.Extensions.Logging";

    // Simple business logic: unit price multiplied by quantity.
    public static decimal OrderTotal(decimal price, int quantity) => price * quantity;
}
