unit MainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.Layouts,
  FMX.StdCtrls, FMX.ListBox, FMX.Controls.Presentation, FMX.Edit, System.Rtti,
  FMX.Grid.Style, FMX.Grid, FMX.ScrollBox;

type
  TMainForm = class(TForm)
    VertScrollBox1: TVertScrollBox;
    LayoutTop: TLayout;
    Label2: TLabel;
    ComboBoxCipherAlgorithm: TComboBox;
    Label5: TLabel;
    ComboBoxInputFormatting: TComboBox;
    Label6: TLabel;
    ComboBoxOutputFormatting: TComboBox;
    Label1: TLabel;
    EditKey: TEdit;
    Label3: TLabel;
    Edit1: TEdit;
    Label4: TLabel;
    EditFiller: TEdit;
    Label7: TLabel;
    ComboBoxChainingMethod: TComboBox;
    CheckBoxLiveCalc: TCheckBox;
    Label8: TLabel;
    StringGridContext: TStringGrid;
    StringColumn1: TStringColumn;
    StringColumn2: TStringColumn;
    Label9: TLabel;
    Label10: TLabel;
    EditPlainText: TEdit;
    EditCipherText: TEdit;
    ButtonEncrypt: TButton;
    ButtonDecrypt: TButton;
    LabelVersion: TLabel;
    procedure FormResize(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure ComboBoxCipherAlgorithmChange(Sender: TObject);
  private
    procedure InitFormatCombos;
    procedure InitCipherCombo;
    procedure InitCipherModes;
    { Private-Deklarationen }
  public
    { Public-Deklarationen }
  end;

var
  FormMain: TMainForm;

implementation

uses
  System.TypInfo, Generics.Collections, FMX.Platform,
  DECBaseClass, DECFormatBase, DECFormat, DECCipherBase, DECCipherModes,
  DECCiphers, DECUtil;

{$R *.fmx}

procedure TMainForm.ComboBoxCipherAlgorithmChange(Sender: TObject);
var
  Context : TCipherContext;
begin
  Context := TDECCipher.ClassByName(
    ComboBoxCipherAlgorithm.Items[ComboBoxCipherAlgorithm.ItemIndex]).Context;

  StringGridContext.RowCount := 7;
  StringGridContext.Cells[0, 0] := 'Key size (bit)';
  StringGridContext.Cells[0, 1] := 'Block size (bit)';
  StringGridContext.Cells[0, 2] := 'Buffer size (bit)';
  StringGridContext.Cells[0, 3] := 'User size (bit)';
  StringGridContext.Cells[0, 4] := 'User save';
  StringGridContext.Cells[0, 5] := 'Cipher mode';
  StringGridContext.Cells[0, 6] := 'Cipher key';

  StringGridContext.Cells[1, 0] :=  (Context.KeySize*8).ToString;
  StringGridContext.Cells[1, 1] :=  (Context.BlockSize*8).ToString;
  StringGridContext.Cells[1, 2] :=  (Context.BufferSize*8).ToString;
  StringGridContext.Cells[1, 3] :=  (Context.UserSize*8).ToString;
  StringGridContext.Cells[1, 4] :=  BoolToStr(Context.UserSave, true);

  if ctBlock in Context.CipherType then
    StringGridContext.Cells[1, 5] := 'block cipher'
  else
    StringGridContext.Cells[1, 5] := 'stream cipher';

  if ctSymmetric in Context.CipherType then
    StringGridContext.Cells[1, 6] := 'symmetric'
  else
    StringGridContext.Cells[1, 6] := 'asymmetric';
end;

procedure TMainForm.FormCreate(Sender: TObject);
var
  AppService : IFMXApplicationService;
begin
  if TPlatformServices.Current.SupportsPlatformService(IFMXApplicationService,
                                                       IInterface(AppService)) then
    LabelVersion.Text := format(LabelVersion.Text, [AppService.AppVersion])
  else
    LabelVersion.Text := format(LabelVersion.Text, ['']);

  InitFormatCombos;
  InitCipherCombo;
  InitCipherModes;
end;

procedure TMainForm.FormResize(Sender: TObject);
begin
  LayoutTop.Width    := VertScrollBox1.Width;
end;

procedure TMainForm.InitFormatCombos;
var
  MyClass : TPair<Int64, TDECClass>;
  Formats : TStringList;
  CopyIdx : Integer;
begin
  Formats := TStringList.Create;

  try
    for MyClass in TDECFormat.ClassList do
      Formats.Add(MyClass.Value.ClassName);

    Formats.Sort;
    ComboBoxInputFormatting.Items.AddStrings(Formats);
    ComboBoxOutputFormatting.Items.AddStrings(Formats);

    if Formats.Count > 0 then
    begin
      if Formats.Find('TFormat_Copy', CopyIdx) then
      begin
        ComboBoxInputFormatting.ItemIndex  := CopyIdx;
        ComboBoxOutputFormatting.ItemIndex := CopyIdx;
      end
      else
      begin
        ComboBoxInputFormatting.ItemIndex  := 0;
        ComboBoxOutputFormatting.ItemIndex := 0;
      end;
    end;
  finally
    Formats.Free;
  end;
end;

procedure TMainForm.InitCipherCombo;
var
  MyClass : TPair<Int64, TDECClass>;
  Ciphers : TStringList;
  CopyIdx : Integer;
begin
  Ciphers := TStringList.Create;

  try
    for MyClass in TDECCipher.ClassList do
      Ciphers.Add(MyClass.Value.ClassName);

    Ciphers.Sort;
    ComboBoxCipherAlgorithm.Items.AddStrings(Ciphers);

    if Ciphers.Count > 0 then
    begin
      if Ciphers.Find('TCipher_Null', CopyIdx) then
        ComboBoxCipherAlgorithm.ItemIndex  := CopyIdx
      else
        ComboBoxCipherAlgorithm.ItemIndex  := 0;
    end;
  finally
    Ciphers.Free;
  end;
end;

procedure TMainForm.InitCipherModes;
var
  Mode : TCipherMode;
begin
  for Mode := low(TCipherMode) to high(TCipherMode) do
  begin
    ComboBoxChainingMethod.Items.Add(System.TypInfo.GetEnumName(
                                       TypeInfo(TCipherMode),
                                       Integer(Mode)));
  end;

  if ComboBoxChainingMethod.Items.Count > 0 then
    ComboBoxChainingMethod.ItemIndex := 0;
end;

end.
