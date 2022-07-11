{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

unit MainFormHashFMX;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo, FMX.Layouts, FMX.ListBox,
  FMX.Edit, DECHashBase, DECFormatBase;

type
  TFormMain = class(TForm)
    VertScrollBox1: TVertScrollBox;
    LayoutBottom: TLayout;
    Label3: TLabel;
    Label4: TLabel;
    ButtonCalc: TButton;
    EditInput: TEdit;
    EditOutput: TEdit;
    Label2: TLabel;
    Label5: TLabel;
    ComboBoxHashFunction: TComboBox;
    Label6: TLabel;
    ComboBoxInputFormatting: TComboBox;
    ComboBoxOutputFormatting: TComboBox;
    LayoutTop: TLayout;
    CheckBoxLiveCalc: TCheckBox;
    LabelVersion: TLabel;
    CheckBoxIsPasswordHash: TCheckBox;
    CheckBoxIsExtensibleOutputHash: TCheckBox;
    LabelHashLength: TLabel;
    EditHashLength: TEdit;
    CheckBoxHasRounds: TCheckBox;
    LabelRounds: TLabel;
    EditRounds: TEdit;
    CheckBoxLastByteBitSize: TCheckBox;
    LabelLastByteBits: TLabel;
    EditLastByteBits: TEdit;
    LayoutSalt: TLayout;
    Label1: TLabel;
    EditSalt: TEdit;
    Label7: TLabel;
    ComboBoxSaltFormatting: TComboBox;
    Label8: TLabel;
    EditCost: TEdit;
    procedure FormCreate(Sender: TObject);
    procedure ButtonCalcClick(Sender: TObject);
    procedure ComboBoxHashFunctionChange(Sender: TObject);
    procedure EditInputChangeTracking(Sender: TObject);
    procedure EditInputKeyUp(Sender: TObject; var Key: Word; var KeyChar: Char;
      Shift: TShiftState);
    procedure EditHashLengthChange(Sender: TObject);
    procedure EditRoundsChange(Sender: TObject);
    procedure VertScrollBox1CalcContentBounds(Sender: TObject;
      var ContentBounds: TRectF);
    procedure EditCostChange(Sender: TObject);
  private
    /// <summary>
    ///   Lists all available hash classes in the hash classes combo box
    /// </summary>
    procedure InitHashCombo;
    /// <summary>
    ///   Lists all available formatting classes in the formatting classes
    ///   combo boxes
    /// </summary>
    procedure InitFormatCombos;
    /// <summary>
    ///   Displays a given error message text in a non modal message box
    /// </summary>
    /// <param name="ErrorMsg">
    ///   Text to show as error message
    /// </param>
    procedure ShowErrorMessage(ErrorMsg: string);
    /// <summary>
    ///   Returns the full class name of the selected hash class.
    /// </summary>
    /// <returns>
    ///   Full class name instead of the displayed algorithm name. It does not
    ///   guard agains having nothing selected.
    /// </returns>
    function  GetSelectedHashClassName: string;
    /// <summary>
    ///   Determine and return the selected class for input format treatment
    /// </summary>
    function GetSelectedInputFormattingClass:TDECFormatClass;
    /// <summary>
    ///   Determines whether the selected hash algorithm is a password hash
    ///   algorithm which requires a salt to be defined in addition to the
    ///   text to be hashed.
    /// </summary>
    function IsSaltablePasswordHash(HashClass: TDECHashClass): Boolean;
  public
  end;

var
  FormMain: TFormMain;

implementation

uses
  DECBaseClass, DECHash, DECHashAuthentication, DECHashInterface,
  DECFormat, DECUtil,
  Generics.Collections, FMX.Platform
  {$IFDEF Android}
  ,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.Helpers,
  Androidapi.JNI.App
  {$ENDIF};

{$R *.fmx}

procedure TFormMain.ButtonCalcClick(Sender: TObject);
var
  Hash                 : TDECHash;
  HashClass            : TDECHashClass;
  InputFormatting      : TDECFormatClass;
  OutputFormatting     : TDECFormatClass;
  SaltFormatting       : TDECFormatClass;
  InputBuffer          : TBytes;
  OutputBuffer         : TBytes;
  ExtensibleInterf     : IDECHashExtensibleOutput;
  LastByteLengthInterf : IDECHashBitsized;
  RoundsInterf         : IDECHashRounds;
  Rounds               : UInt8;
begin
  if ComboBoxInputFormatting.ItemIndex >= 0 then
    // Find the class type of the selected formatting class
    InputFormatting := GetSelectedInputFormattingClass
  else
  begin
    ShowErrorMessage('No input format selected');
    exit;
  end;

  if ComboBoxOutputFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class
    OutputFormatting := TDECFormat.ClassByName(
      ComboBoxOutputFormatting.Items[ComboBoxOutputFormatting.ItemIndex]);
  end
  else
  begin
    ShowErrorMessage('No input format selected');
    exit;
  end;

  if ComboBoxHashFunction.ItemIndex >= 0 then
  begin
    // Find the class type of the selected hash class and create an instance of it
   Hash := TDECHash.ClassByName(GetSelectedHashClassName).Create;

    if Supports(Hash.ClassType, IDECHashExtensibleOutput) then
    begin
      ExtensibleInterf := (Hash as IDECHashExtensibleOutput);
      ExtensibleInterf.HashSize := EditHashLength.Text.ToInteger;
    end
    else
      ExtensibleInterf := nil;

    if Supports(Hash.ClassType, IDECHashBitsized) then
    begin
      LastByteLengthInterf := (Hash as IDECHashBitsized);
      LastByteLengthInterf.FinalBitLength := EditLastByteBits.Text.ToInteger;
    end
    else
      LastByteLengthInterf := nil;

    if Supports(Hash.ClassType, IDECHashRounds) then
    begin
      RoundsInterf := (Hash as IDECHashRounds);
      Rounds := EditRounds.Text.ToInteger;

      // If value is not in range we don't dis´play any error message here
      // because we already displayed one in OnChange of the edit, means when
      // the edit lost focus. This if here is only to prevent that after closing
      // the error message the user clicks the calc button again. In that case we
      // simply skip calculation completely.
      if (Rounds >= RoundsInterf.GetMinRounds) and
         (Rounds <= RoundsInterf.GetMaxRounds) then
        RoundsInterf.Rounds := EditRounds.Text.ToInteger
      else
        Exit;
    end
    else
      RoundsInterf := nil;

    // set the salt property
    HashClass := TDECHash.ClassByName(GetSelectedHashClassName);
    if IsSaltablePasswordHash(HashClass) then
    begin
      if EditSalt.Text.IsEmpty then
      begin
        ShowErrorMessage('No salt value entered');
        exit;
      end;

      if (ComboBoxSaltFormatting.ItemIndex >= 0) then
        // Find the class type of the selected formatting class
        SaltFormatting := TDECFormat.ClassByName(
          ComboBoxSaltFormatting.Items[ComboBoxSaltFormatting.ItemIndex])
      else
      begin
        ShowErrorMessage('No salt format selected');
        exit;
      end;

      InputBuffer  := System.SysUtils.BytesOf(EditSalt.Text);
      if InputFormatting.IsValid(InputBuffer) then
        TDECPasswordHash(Hash).Salt := SaltFormatting.Decode(InputBuffer)
      else
        ShowErrorMessage('Salt has wrong format');
    end;

    // Set the BCrypt specific cost factor. Might be more generalized when
    // further password hashes are added.
    if (HashClass = THash_BCrypt) then
      THash_BCrypt(Hash).Cost := EditCost.Text.ToInteger;

    try
      InputBuffer  := System.SysUtils.BytesOf(EditInput.Text);

      if InputFormatting.IsValid(InputBuffer) then
      begin
        OutputBuffer := Hash.CalcBytes(InputFormatting.Decode(InputBuffer));

        EditOutput.Text := string(DECUtil.BytesToRawString(OutputFormatting.Encode(OutputBuffer)));
      end
      else
        ShowErrorMessage('Input has wrong format');
    finally
      // We must free the hash instance only, if we didn't use the interface
      // for extensible hash algorithms to set the output hash length.
      if (not Assigned(ExtensibleInterf)) and
         (not Assigned(LastByteLengthInterf)) and
         (not Assigned(RoundsInterf)) then
        Hash.Free;
    end;
  end;
end;

procedure TFormMain.ShowErrorMessage(ErrorMsg: string);
{$IF RTLVersion > 30}
var
  AsyncDlg : IFMXDialogServiceASync;
{$ENDIF}
begin
  {$IF RTLVersion > 30}
  if TPlatformServices.Current.SupportsPlatformService(IFMXDialogServiceAsync,
                                                       IInterface(AsyncDlg)) then
    AsyncDlg.MessageDialogAsync(Translate(ErrorMsg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], TMsgDlgBtn.mbOk, 0,
    procedure (const AResult: TModalResult)
    begin
    end);
  {$ELSE}
  MessageDlg(Translate(ErrorMsg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], 0);
  {$ENDIF}
end;

procedure TFormMain.VertScrollBox1CalcContentBounds(Sender: TObject;
  var ContentBounds: TRectF);
begin
  LayoutTop.Width    := VertScrollBox1.ClientWidth;
  LayoutSalt.Width   := VertScrollBox1.ClientWidth;
  LayoutBottom.Width := VertScrollBox1.ClientWidth;
end;

procedure TFormMain.ComboBoxHashFunctionChange(Sender: TObject);
var
  HashClass    : TDECHashClass;
  LayoutHeight : Single;
begin
  HashClass := TDECHash.ClassByName(GetSelectedHashClassName);

  CheckBoxIsPasswordHash.IsChecked :=
    HashClass.IsPasswordHash;

  // Make the salt fields visible only when a password hash algorithm supporting
  // a salt value has been selected.
  LayoutSalt.Visible := IsSaltablePasswordHash(HashClass);
  if LayoutSalt.Visible then
  begin
    if ComboBoxSaltFormatting.ItemIndex < 0 then
      ComboBoxSaltFormatting.ItemIndex := 0;

    EditCost.Enabled := HashClass = THash_BCrypt;

    LayoutBottom.Position.Y := LayoutSalt.Position.Y + LayoutSalt.Height;
  end
  else
    LayoutBottom.Position.Y := LayoutTop.Opacity + LayoutTop.Height;

  if Supports(HashClass, IDECHashExtensibleOutput) then
  begin
    CheckBoxIsExtensibleOutputHash.IsChecked := true;
    EditHashLength.Enabled                   := true;
    LabelHashLength.Enabled                  := true;
  end
  else
  begin
    CheckBoxIsExtensibleOutputHash.IsChecked := false;
    EditHashLength.Enabled                   := false;
    LabelHashLength.Enabled                  := false;
  end;

  if Supports(HashClass, IDECHashRounds) then
  begin
    CheckBoxHasRounds.IsChecked := true;
    LabelRounds.Enabled         := true;
    EditRounds.Enabled          := true;
  end
  else
  begin
    CheckBoxHasRounds.IsChecked := false;
    LabelRounds.Enabled         := false;
    EditRounds.Enabled          := false;
  end;

  if Supports(HashClass, IDECHashBitsized) then
  begin
    CheckBoxLastByteBitSize.IsChecked := true;
    LabelLastByteBits.Enabled         := true;
    EditLastByteBits.Enabled          := true;
  end
  else
  begin
    CheckBoxLastByteBitSize.IsChecked := false;
    LabelLastByteBits.Enabled         := false;
    EditLastByteBits.Enabled          := false;
  end;

  LayoutHeight := LayoutTop.Height + LayoutBottom.Height;
  if LayoutSalt.Visible then
    LayoutHeight := LayoutHeight + LayoutSalt.Height;

  if (Height > Screen.Height) then
    Height := trunc(Screen.Height)
  else
    if (ClientHeight < LayoutHeight) and (LayoutHeight < Screen.Height) then
      ClientHeight := trunc(LayoutHeight)
    else
      Height := trunc(Screen.Height);
end;

function TFormMain.IsSaltablePasswordHash(HashClass: TDECHashClass): Boolean;
var
  Hash : TDECHash;
begin
  Result := false;

  if HashClass.IsPasswordHash then
  begin
    Hash := HashClass.Create;

    try
      if Supports(Hash.ClassType, IDECHashPassword) then
        Result := (TDECPasswordHash(Hash).MaxSaltLength > 0);
    finally
      Hash.Free;
    end;
  end;
end;

procedure TFormMain.EditCostChange(Sender: TObject);
var
  Cost      : Integer;
  HashClass : TDECHashClass;

  MinCost,
  MaxCost   : Byte;
begin
  if ((Sender as TEdit).Text.Length > 0) then
  begin
    Cost := (Sender as TEdit).Text.ToInteger;
    // Needs to be changed when further password hashes are added
    HashClass := TDECHash.ClassByName(GetSelectedHashClassName);
    MinCost := THash_BCrypt(HashClass).MinCost;
    MaxCost := THash_BCrypt(HashClass).MaxCost;

    if (Cost < MinCost) or
       (Cost > MaxCost) then
      ShowErrorMessage(Format('Invalid input. Cost must be between %0:d and %1:d',
                              [MinCost, MaxCost]));

    if (Cost < MinCost) then
      (Sender as TEdit).Text := MinCost.ToString;

    if (Cost > MaxCost) then
      (Sender as TEdit).Text := MaxCost.ToString;
  end;
end;

procedure TFormMain.EditHashLengthChange(Sender: TObject);
begin
  if ((Sender as TEdit).Text.Length > 0) and ((Sender as TEdit).Text <> '0') then
    ButtonCalcClick(self);
end;

procedure TFormMain.EditInputChangeTracking(Sender: TObject);
var
  InputFormatting : TDECFormatClass;
begin
  if CheckBoxLiveCalc.IsChecked then
  begin
    // Check if input is valid
    InputFormatting := GetSelectedInputFormattingClass;
    if InputFormatting.IsValid(RawByteString(EditInput.Text)) then
      ButtonCalcClick(self);
  end;
end;

procedure TFormMain.EditInputKeyUp(Sender: TObject; var Key: Word;
  var KeyChar: Char; Shift: TShiftState);
begin
  if (Key = vkReturn) then
    ButtonCalcClick(self);
end;

procedure TFormMain.EditRoundsChange(Sender: TObject);
var
  Hash         : TDECHash;
  RoundsInterf : IDECHashRounds;
begin
  Hash := TDECHash.ClassByName(GetSelectedHashClassName).Create;

  if Supports(Hash, IDECHashRounds, RoundsInterf) then
  begin
    if ((Sender as TEdit).Text.Length > 0) and ((Sender as TEdit).Text <> '0') and
       ((Sender as TEdit).Text.ToInteger >= Integer(RoundsInterf.GetMinRounds)) and
       ((Sender as TEdit).Text.ToInteger <= Integer(RoundsInterf.GetMaxRounds)) then
        ButtonCalcClick(self)
    else
      ShowErrorMessage(Format('Invalid input. Rounds must be between %0:d and %1:d',
                              [RoundsInterf.GetMinRounds, RoundsInterf.GetMaxRounds]));
  end
  else
    Hash.Free;
end;

procedure TFormMain.FormCreate(Sender: TObject);
var
  AppService : IFMXApplicationService;
begin
  if TPlatformServices.Current.SupportsPlatformService(IFMXApplicationService,
                                                       IInterface(AppService)) then
    LabelVersion.Text := format(LabelVersion.Text, [AppService.AppVersion])
  else
    LabelVersion.Text := format(LabelVersion.Text, ['']);

  InitHashCombo;
  InitFormatCombos;
end;

procedure TFormMain.InitFormatCombos;
var
  MyClass : TPair<Int64, TDECClass>;
  Formats : TStringList;
  CopyIdx : Integer;
begin
  Formats := TStringList.Create;

  try
    for MyClass in TDECFormat.ClassList do
      Formats.Add(MyClass.Value.GetShortClassName);

    Formats.Sort;
    ComboBoxInputFormatting.Items.AddStrings(Formats);
    ComboBoxOutputFormatting.Items.AddStrings(Formats);
    ComboBoxSaltFormatting.Items.AddStrings(Formats);

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

procedure TFormMain.InitHashCombo;
var
  MyClass : TPair<Int64, TDECClass>;
  Hashes  : TStringList;
begin
  Hashes := TStringList.Create;

  try
    for MyClass in TDECHash.ClassList do
      Hashes.Add(MyClass.Value.GetShortClassName);

    Hashes.Sort;
    ComboBoxHashFunction.Items.AddStrings(Hashes);

    if Hashes.Count > 0 then
      ComboBoxHashFunction.ItemIndex := 0;
  finally
    Hashes.Free;
  end;
end;

function TFormMain.GetSelectedHashClassName: string;
begin
  Result := 'THash_' + ComboBoxHashFunction.Items[ComboBoxHashFunction.ItemIndex];
end;

function TFormMain.GetSelectedInputFormattingClass: TDECFormatClass;
begin
  // Find the class type of the selected formatting class and create an instance of it
  Result := TDECFormat.ClassByName(
    ComboBoxInputFormatting.Items[ComboBoxInputFormatting.ItemIndex]);
end;

end.
