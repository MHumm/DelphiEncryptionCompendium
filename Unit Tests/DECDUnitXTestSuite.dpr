{.$DEFINE GUI}
{.$DEFINE MobileGUI}
program DECDUnitXTestSuite;

// In order to run DEC Unit tests via DUnitX framework the $DEFINE DUnitX define
// in defines.inc must be enabled, as it makes all the unit test units DUnitX
// compatible
{$I Tests\defines.inc}

{$IFNDEF GUI}
{$IFNDEF TESTINSIGHT}
{$APPTYPE CONSOLE}
{$ENDIF}
{$ENDIF}

{$STRONGLINKTYPES ON}
uses
  System.SysUtils,
  {$IFDEF TESTINSIGHT}
  TestInsight.DUnitX,
  {$ENDIF }
  {$IFDEF GUI}
  DUnitX.Loggers.GUIX,
  {$ENDIF }
  {$IFDEF MobileGUI}
  {$ENDIF }
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  DECCRC in '..\Source\DECCRC.pas',
  DECUtil in '..\Source\DECUtil.pas',
  DECBaseClass in '..\Source\DECBaseClass.pas',
  DECTypes in '..\Source\DECTypes.pas',
  TestDECCRC in 'Tests\TestDECCRC.pas',
  DECFormat in '..\Source\DECFormat.pas',
  DECFormatBase in '..\Source\DECFormatBase.pas',
  TestDECFormatBase in 'Tests\TestDECFormatBase.pas',
  TestDECFormat in 'Tests\TestDECFormat.pas',
  TestDECUtil in 'Tests\TestDECUtil.pas',
  TestDECHash in 'Tests\TestDECHash.pas',
  DECHash in '..\Source\DECHash.pas',
  DECHashBase in '..\Source\DECHashBase.pas',
  DECData in '..\Source\DECData.pas',
  TestDECCipher in 'Tests\TestDECCipher.pas',
  DECCipherBase in '..\Source\DECCipherBase.pas',
  DECCiphers in '..\Source\DECCiphers.pas',
  DECCipherModes in '..\Source\DECCipherModes.pas',
  DECCipherFormats in '..\Source\DECCipherFormats.pas',
  TestDECCipherModes in 'Tests\TestDECCipherModes.pas',
  DECUtilRawByteStringHelper in '..\Source\DECUtilRawByteStringHelper.pas',
  TestDECTestDataContainer in 'Tests\TestDECTestDataContainer.pas',
  TestDECBaseClass in 'Tests\TestDECBaseClass.pas',
  DECCipherInterface in '..\Source\DECCipherInterface.pas',
  DECHashInterface in '..\Source\DECHashInterface.pas',
  TestDECCipherFormats in 'Tests\TestDECCipherFormats.pas',
  DECDataCipher in '..\Source\DECDataCipher.pas',
  DECDataHash in '..\Source\DECDataHash.pas',
  TestDECHashKDF in 'Tests\TestDECHashKDF.pas',
  TestDECRandom in 'Tests\TestDECRandom.pas',
  DECRandom in '..\Source\DECRandom.pas';

var
  runner : ITestRunner;
  results : IRunResults;
  logger : ITestLogger;
  nunitLogger : ITestLogger;
begin
{$IFDEF TESTINSIGHT}
  TestInsight.DUnitX.RunRegisteredTests;
  exit;
{$ENDIF}

//{$IFDEF GUI}
// // DUnitX.Loggers.GUIX.GUIXTestRunner.Run.Execute;
////  DUnitX.Loggers.GUIX.GUIXTestRunner.Run;
//  DUnitX.Loggers.GUI.VCL.Run;
//  exit;
//{$ENDIF}

  try
    //Check command line options, will exit if invalid
    TDUnitX.CheckCommandLine;
    //Create the test runner
    runner := TDUnitX.CreateRunner;
    //Tell the runner to use RTTI to find Fixtures
    runner.UseRTTI := True;
    //tell the runner how we will log things
    //Log to the console window
    {$IFDEF GUI}
    logger := TGUIXTestRunner.Create(nil);
    {$ELSE}
    logger := TDUnitXConsoleLogger.Create(true);
    {$ENDIF}
    runner.AddLogger(logger);
    //Generate an NUnit compatible XML File
    nunitLogger := TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile);
    runner.AddLogger(nunitLogger);
    runner.FailsOnNoAsserts := False; //When true, Assertions must be made during tests;

    //Run tests
    results := runner.Execute;
    if not results.AllPassed then
      System.ExitCode := EXIT_ERRORS;

    {$IFNDEF CI}
    //We don't want this happening when running under CI.
    if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
    begin
      System.Write('Done.. press <Enter> key to quit.');
      System.Readln;
    end;
    {$ENDIF}
  except
    on E: Exception do
      System.Writeln(E.ClassName, ': ', E.Message);
  end;
end.
