program DECDUnitXTestSuite;

// DUnitX is turned on by this project's compiler defines in the .dproj
// (Debug/Release/TestInsight), not by defining it in TestDefines.inc.
// The .inc must stay without DUnitX so that when the same test units are
// compiled inside DECDUnitTestSuite they still use classic DUnit.
{$INCLUDE Tests\TestDefines.inc}

{$IFNDEF TESTINSIGHT}
{$APPTYPE CONSOLE}
{$ENDIF}
{$STRONGLINKTYPES ON}

uses
  System.SysUtils,
  {$IFDEF TESTINSIGHT}
  TestInsight.DUnitX,
  {$ENDIF}
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  TestDECCRC in 'Tests\TestDECCRC.pas',
  TestDECFormatBase in 'Tests\TestDECFormatBase.pas',
  TestDECFormat in 'Tests\TestDECFormat.pas',
  TestDECUtil in 'Tests\TestDECUtil.pas',
  TestDECHash in 'Tests\TestDECHash.pas',
  TestDECCipher in 'Tests\TestDECCipher.pas',
  TestDECCipherModes in 'Tests\TestDECCipherModes.pas',
  TestDECTestDataContainer in 'Tests\TestDECTestDataContainer.pas',
  TestDECBaseClass in 'Tests\TestDECBaseClass.pas',
  TestDECCipherFormats in 'Tests\TestDECCipherFormats.pas',
  TestDECHashKDF in 'Tests\TestDECHashKDF.pas',
  TestDECRandom in 'Tests\TestDECRandom.pas',
  TestDECHashMAC in 'Tests\TestDECHashMAC.pas',
  TestDECHashSHA3 in 'Tests\TestDECHashSHA3.pas',
  TestDECCipherModesGCM in 'Tests\TestDECCipherModesGCM.pas',
  TestDECCipherModesCCM in 'Tests\TestDECCipherModesCCM.pas',
  TestDECCipherPaddings in 'Tests\TestDECCipherPaddings.pas',
  TestDECZIPHelper in 'Tests\TestDECZIPHelper.pas',
  AuthenticatedCiphersCommonTestData in 'Tests\AuthenticatedCiphersCommonTestData.pas';

{ keep comment here to protect the following conditional from being removed by the IDE when adding a unit }
{$IFNDEF TESTINSIGHT}
var
  runner: ITestRunner;
  results: IRunResults;
  logger: ITestLogger;
  nunitLogger: ITestLogger;
{$ENDIF}
begin
{$IFDEF TESTINSIGHT}
  TestInsight.DUnitX.RunRegisteredTests;
{$ELSE}
  try
    ReportMemoryLeaksOnShutdown := True;
    TDUnitX.CheckCommandLine;

    runner := TDUnitX.CreateRunner;
    // Fixtures register in unit initialization — avoid double discovery:
    runner.UseRTTI := False;
    runner.FailsOnNoAsserts := False; // True after parity period

    {$IFDEF CI}
    TDUnitX.Options.ConsoleMode := TDunitXConsoleMode.Off;
    {$ENDIF}

    if TDUnitX.Options.ConsoleMode <> TDunitXConsoleMode.Off then
    begin
      logger := TDUnitXConsoleLogger.Create(
        TDUnitX.Options.ConsoleMode = TDunitXConsoleMode.Quiet);
      runner.AddLogger(logger);
    end;

    // NUnit XML for CI and local regression comparison
    nunitLogger := TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile);
    runner.AddLogger(nunitLogger);

    results := runner.Execute;
    if not results.AllPassed then
      System.ExitCode := EXIT_ERRORS;

    {$IFNDEF CI}
    if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
    begin
      System.Write('Done.. press <Enter> key to quit.');
      System.Readln;
    end;
    {$ENDIF}
  except
    on E: Exception do
    begin
      System.Writeln(E.ClassName, ': ', E.Message);
      System.ExitCode := 1;
    end;
  end;
{$ENDIF}
end.
