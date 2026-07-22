/// <summary>
///   When DUnitX is defined (typically via DECDUnitXTestSuite project options),
///   unit tests compile against DUnitX + DUnitCompatibility.
///   When undefined (DECDUnitTestSuite), classic DUnit TestFramework is used.
///   Do not enable the define here permanently — that would break the DUnit project.
/// </summary>
{.$DEFINE DUnitX}
