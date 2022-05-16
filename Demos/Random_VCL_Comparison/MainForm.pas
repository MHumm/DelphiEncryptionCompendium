unit MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, VclTee.TeeGDIPlus, Vcl.StdCtrls,
  VCLTee.TeEngine, Vcl.ExtCtrls, VCLTee.TeeProcs, VCLTee.Chart, VCLTee.Series;

type
  /// <summary>
  ///   Our random numbers
  /// </summary>
  TValues = array[0..255] of UInt32;

  TRandomCompareForm = class(TForm)
    Label1: TLabel;
    EditRepetitions: TEdit;
    Label2: TLabel;
    Chart1: TChart;
    ButtonStart: TButton;
    Series1: TLineSeries;
    Series2: TLineSeries;
    procedure ButtonStartClick(Sender: TObject);
  private
    procedure ClearValues(var Values: TValues);
    procedure DisplayValues(const Values: TValues; Series: TLineSeries);
    procedure GenerateRTLValues(var Values: TValues; Repeats: UInt32);
    procedure GenerateDECValues(var Values: TValues; Repeats: UInt32);
  public
  end;

var
  RandomCompareForm: TRandomCompareForm;

implementation

uses
  DECRandom;

{$R *.dfm}

procedure TRandomCompareForm.ButtonStartClick(Sender: TObject);
var
  Max    : UInt32;
  Values : TValues;
begin
  Max := StrToInt(EditRepetitions.Text);

  Series1.Clear;
  Series2.Clear;

  ClearValues(Values);
  GenerateDECValues(Values, Max);
  DisplayValues(Values, Series1);

  ClearValues(Values);
  GenerateRTLValues(Values, Max);
  DisplayValues(Values, Series2);
end;

procedure TRandomCompareForm.GenerateDECValues(var Values  : TValues;
                                               Repeats     : UInt32);
var
  i, n : UInt32;
begin
  for i := 0 to Repeats do
  begin
    for n := 0 to 255 do
      inc(Values[RandomBytes(1)[0]]);
  end;
end;

procedure TRandomCompareForm.GenerateRTLValues(var Values  : TValues;
                                               Repeats     : UInt32);
var
  i, n : UInt32;
begin
  for i := 0 to Repeats do
  begin
    for n := 0 to 255 do
      inc(Values[Random(256)]);
  end;
end;

procedure TRandomCompareForm.ClearValues(var Values: TValues);
var
  i: Cardinal;
begin
  for i := Low(Values) to High(Values) do
    Values[i] := 0;
end;

procedure TRandomCompareForm.DisplayValues(const Values : TValues;
                                           Series       : TLineSeries);
var
  i : Integer;
begin
  for i := 0 to 255 do
    Series.AddXY(i, Values[i]);
end;

end.
