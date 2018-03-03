// Simple project group for easier DEC 6.0 development
// (c) 2016 Markus Humm
program DEC60;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  DECBaseClass in 'DECBaseClass.pas',
  DECCipherBase in 'DECCipherBase.pas',
  DECCRC in 'DECCRC.pas',
  DECData in 'DECData.pas',
  DECFormat in 'DECFormat.pas',
  DECFormatBase in 'DECFormatBase.pas',
  DECHash in 'DECHash.pas',
  DECRandom in 'DECRandom.pas',
  DECUtil in 'DECUtil.pas',
  DECCiphers in 'DECCiphers.pas',
  DECHashBase in 'DECHashBase.pas',
  DECCipherFormats in 'DECCipherFormats.pas',
  DECTypes in 'DECTypes.pas',
  DECCipherModes in 'DECCipherModes.pas';

begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
