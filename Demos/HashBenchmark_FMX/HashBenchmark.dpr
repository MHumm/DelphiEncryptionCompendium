program HashBenchmark;

uses
  System.StartUpCopy,
  FMX.Forms,
  MainFormHashBenchmark in 'MainFormHashBenchmark.pas' {FormMain};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
