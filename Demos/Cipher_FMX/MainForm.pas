unit MainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.Layouts,
  FMX.StdCtrls, FMX.ListBox, FMX.Controls.Presentation, FMX.Edit, System.Rtti,
  FMX.Grid.Style, FMX.Grid, FMX.ScrollBox, DECCipherBase;

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
    EditInitVector: TEdit;
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
    procedure ButtonEncryptClick(Sender: TObject);
    procedure EditPlainTextChangeTracking(Sender: TObject);
    procedure ButtonDecryptClick(Sender: TObject);
    procedure FormKeyUp(Sender: TObject; var Key: Word; var KeyChar: Char;
      Shift: TShiftState);
  private
    procedure InitFormatCombos;
    procedure InitCipherCombo;
    procedure InitCipherModes;
    procedure ShowErrorMessage(ErrorMsg: string);
    function GetSelectedCipherMode: TCipherMode;
    /// <summary>
    ///   Calls the Android home screen into foreground so that when pressing
    ///   back the app goes into background properly and when pressing the app
    ///   icon in the app drawer or on home screen it returns to the same point
    ///   it was.
    /// </summary>
    procedure OpenHomeScreen;
  public
  end;

var
  FormMain: TMainForm;

implementation

uses
  System.TypInfo, Generics.Collections, FMX.Platform,
  DECBaseClass, DECFormatBase, DECFormat, DECCipherModes,
  DECCipherFormats, DECCiphers, DECUtil
  {$IFDEF Android}
  ,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.Helpers,
  Androidapi.JNI.App
  {$ENDIF};

{$R *.fmx}

procedure TMainForm.ButtonDecryptClick(Sender: TObject);
begin
//
end;

procedure TMainForm.ButtonEncryptClick(Sender: TObject);
var
  Cipher           : TDECCipher;
  InputFormatting  : TDECFormatClass;
  OutputFormatting : TDECFormatClass;
  InputBuffer      : TBytes;
  OutputBuffer     : TBytes;
begin
  if ComboBoxInputFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    InputFormatting := TDECFormat.ClassByName(
      ComboBoxInputFormatting.Items[ComboBoxInputFormatting.ItemIndex]);
  end
  else
  begin
    ShowErrorMessage('No input format selected');
    exit;
  end;

  if ComboBoxOutputFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    OutputFormatting := TDECFormat.ClassByName(
      ComboBoxOutputFormatting.Items[ComboBoxOutputFormatting.ItemIndex]);
  end
  else
  begin
    ShowErrorMessage('No output format selected');
    exit;
  end;

  if EditKey.Text.IsEmpty or EditInitVector.Text.IsEmpty or EditFiller.Text.IsEmpty then
  begin
    ShowErrorMessage('No key, initialization vector or filler byte given');
    exit;
  end;

  if ComboBoxCipherAlgorithm.ItemIndex >= 0 then
  begin
    // Find the class type of the selected hash class and create an instance of it
    Cipher := TDECCipher.ClassByName(
      ComboBoxCipherAlgorithm.Items[ComboBoxCipherAlgorithm.ItemIndex]).Create;

    if TFormat_HEX.IsValid(RawByteString(EditInitVector.Text)) and
       TFormat_HEX.IsValid(RawByteString(EditFiller.Text)) then
    begin
      Cipher.Init(RawByteString(EditKey.Text),
                  TFormat_HEX.Decode(RawByteString(EditInitVector.Text)),
                  StrToInt('0x' + EditFiller.Text));

      Cipher.Mode := GetSelectedCipherMode;
    end
    else
    begin
      ShowErrorMessage('Init vector or filler byte  not given in hexadecimal representation');
      exit;
    end;

    try
      InputBuffer  := System.SysUtils.BytesOf(EditPlainText.Text);

      if InputFormatting.IsValid(InputBuffer) then
      begin
// Warum springt er hier direkt die nur für einen Block gültige
// DoEncode an, statt der Blockverkettung nutzenden aus DECCipherModes?
// Was ist hier anders als im Console basierten Programm?
        OutputBuffer := (Cipher as TDECFormattedCipher).EncodeBytes(InputFormatting.Decode(InputBuffer));

        EditCipherText.Text := DECUtil.BytesToRawString(OutputFormatting.Encode(OutputBuffer));
      end
      else
        ShowErrorMessage('Input has wrong format');
    finally
      Cipher.Free;
    end;
  end
  else
    ShowErrorMessage('No cipher algorithm selected');
end;

function TMainForm.GetSelectedCipherMode:TCipherMode;
begin
  // Determine selected block chaining method via RTTI (runtime type information)
  result := TCipherMode(System.TypInfo.GetEnumValue(
              TypeInfo(TCipherMode),
              ComboBoxChainingMethod.Items[ComboBoxChainingMethod.ItemIndex]));
end;

procedure TMainForm.ShowErrorMessage(ErrorMsg: string);
var
  AsyncDlg : IFMXDialogServiceASync;
begin
  if TPlatformServices.Current.SupportsPlatformService(IFMXDialogServiceAsync,
                                                       IInterface(AsyncDlg)) then
    AsyncDlg.MessageDialogAsync(Translate(ErrorMsg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], TMsgDlgBtn.mbOk, 0,
    procedure (const AResult: TModalResult)
    begin
    end);
end;

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

procedure TMainForm.EditPlainTextChangeTracking(Sender: TObject);
begin
  if CheckBoxLiveCalc.IsChecked then
  begin
    if ActiveControl = ButtonEncrypt then
      ButtonEncryptClick(self)
    else
      ButtonDecryptClick(self);
  end;
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

procedure TMainForm.FormKeyUp(Sender: TObject; var Key: Word; var KeyChar: Char;
  Shift: TShiftState);
begin
  {$IFDEF Android}
  if Key = vkHardwareBack then
    OpenHomeScreen;

  Key := 0;
  {$ENDIF}
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

procedure TMainForm.OpenHomeScreen;
{$IFDEF ANDROID}
var
  Intent: JIntent;
{$ENDIF ANDROID}
begin
{$IFDEF ANDROID}
  Intent := TJIntent.Javaclass.init(TJIntent.JavaClass.ACTION_MAIN);
  Intent.addCategory(TJIntent.JavaClass.CATEGORY_HOME);
  Intent.setFlags(TjIntent.JavaClass.FLAG_ACTIVITY_NEW_TASK);
  TAndroidhelper.Activity.startActivity(Intent);
{$ENDIF ANDROID}
{$IFDEF IOS}
  NavigationController.popToRootViewControllerAnimated(true);
{$ENDIF}
end;

end.
