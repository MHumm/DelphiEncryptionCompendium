unit MainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo, FMX.Layouts, FMX.ListBox,
  FMX.Edit;

type
  TMainForm = class(TForm)
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
    Label1: TLabel;
    CheckBoxIsPasswordHash: TCheckBox;
    procedure FormCreate(Sender: TObject);
    procedure FormResize(Sender: TObject);
    procedure ButtonCalcClick(Sender: TObject);
    procedure EditInputKeyDown(Sender: TObject; var Key: Word;
      var KeyChar: Char; Shift: TShiftState);
    procedure ComboBoxHashFunctionChange(Sender: TObject);
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
  public
  end;

var
  Form1: TMainForm;

implementation

uses
  DECBaseClass, DECHashBase, DECHash, DECFormatBase, DECFormat, Generics.Collections;

{$R *.fmx}

procedure TMainForm.ButtonCalcClick(Sender: TObject);
var
  Hash             : TDECHash;
  InputFormatting  : TDECFormatClass;
  OutputFormatting : TDECFormatClass;
  InputText        : string;
begin
  if ComboBoxInputFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    InputFormatting := TDECFormat.ClassByName(
      ComboBoxInputFormatting.Items[ComboBoxInputFormatting.ItemIndex]);
  end
  else
    exit;

  if ComboBoxOutputFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    OutputFormatting := TDECFormat.ClassByName(
      ComboBoxOutputFormatting.Items[ComboBoxOutputFormatting.ItemIndex]);
  end
  else
    exit;

  if ComboBoxHashFunction.ItemIndex >= 0 then
  begin
    // Find the class type of the selected hash class and create an instance of it
    Hash := TDECHash.ClassByName(
      ComboBoxHashFunction.Items[ComboBoxHashFunction.ItemIndex]).Create;

    try
      Hash.Init;
// Problem: zumindest unter Windows konvertiert BytesOf via ANSI?!
      InputText := StringOf(InputFormatting.Encode(System.SysUtils.BytesOf(EditInput.Text)));
      EditOutput.Text := Hash.CalcString(InputText, OutputFormatting);
      // Ensure that the internally allocated memory is being freed AND cleared
//      Hash.Done;
    finally
      Hash.Free;
    end;
  end;
end;

procedure TMainForm.ComboBoxHashFunctionChange(Sender: TObject);
begin
  CheckBoxIsPasswordHash.IsChecked :=
    TDECHash.ClassByName(
      ComboBoxHashFunction.Items[ComboBoxHashFunction.ItemIndex]).IsPasswordHash;
end;

procedure TMainForm.EditInputKeyDown(Sender: TObject; var Key: Word;
  var KeyChar: Char; Shift: TShiftState);
begin
  // KeyDownEvent is being used because when continously pressing the backspace
  // key KeyUp is only fired after releasing it
  if (Key = vkReturn) or CheckBoxLiveCalc.IsChecked then
    ButtonCalcClick(self);
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  InitHashCombo;
  InitFormatCombos;
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

procedure TMainForm.InitHashCombo;
var
  MyClass : TPair<Int64, TDECClass>;
  Hashes  : TStringList;
begin
  Hashes := TStringList.Create;

  try
    for MyClass in TDECHash.ClassList do
      Hashes.Add(MyClass.Value.ClassName);

    Hashes.Sort;
    ComboBoxHashFunction.Items.AddStrings(Hashes);

    if Hashes.Count > 0 then
      ComboBoxHashFunction.ItemIndex := 0;
  finally
    Hashes.Free;
  end;
end;

procedure TMainForm.FormResize(Sender: TObject);
begin
  LayoutTop.Width    := VertScrollBox1.Width;
  LayoutBottom.Width := VertScrollBox1.Width;
end;

end.
