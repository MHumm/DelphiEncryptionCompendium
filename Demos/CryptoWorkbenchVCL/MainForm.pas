unit MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls,
  Vcl.ButtonGroup, System.ImageList, Vcl.ImgList, System.Actions, Vcl.ActnList,
  Vcl.PlatformDefaultStyleActnCtrls, Vcl.ActnMan, Vcl.ToolWin,
  Vcl.CategoryButtons;

type
  TFormMain = class(TForm)
    PageControlMain: TPageControl;
    TabSheetCRC: TTabSheet;
    TabSheetHash: TTabSheet;
    TabSheetCipher: TTabSheet;
    TabSheetRandom: TTabSheet;
    TabSheetAbout: TTabSheet;
    ImageListCategory: TImageList;
    PageControlCipher: TPageControl;
    TabSheetBasic: TTabSheet;
    TabSheetAdvanced: TTabSheet;
    Label1: TLabel;
    Label2: TLabel;
    TabSheetFormatConversion: TTabSheet;
    CoolBar1: TCoolBar;
    CategoryButtons: TCategoryButtons;
    GroupBox1: TGroupBox;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    MemoFormatSourceText: TMemo;
    MemoFormatOutput: TMemo;
    ComboSimpleFormat: TComboBox;
    ButtonSimpleFormat: TButton;
    procedure ButtonGroupMainMenuItems0Click(Sender: TObject);
    procedure ButtonGroupMainMenuItems1Click(Sender: TObject);
    procedure ButtonGroupMainMenuItems2Click(Sender: TObject);
    procedure ButtonGroupMainMenuItems3Click(Sender: TObject);
    procedure ButtonGroupMainMenuItems4Click(Sender: TObject);
    procedure ButtonGroupMainMenuItems5Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private-Deklarationen }
  public
    { Public-Deklarationen }
  end;

var
  FormMain: TFormMain;

implementation

{$R *.dfm}

procedure TFormMain.ButtonGroupMainMenuItems0Click(Sender: TObject);
begin
  PageControlMain.ActivePage := TabSheetFormatConversion;
end;

procedure TFormMain.ButtonGroupMainMenuItems1Click(Sender: TObject);
begin
  PageControlMain.ActivePage := TabSheetCRC;
end;

procedure TFormMain.ButtonGroupMainMenuItems2Click(Sender: TObject);
begin
  PageControlMain.ActivePage := TabSheetHash;
end;

procedure TFormMain.ButtonGroupMainMenuItems3Click(Sender: TObject);
begin
  PageControlMain.ActivePage := TabSheetCipher;
  // Unter PageControl beachten
end;

procedure TFormMain.ButtonGroupMainMenuItems4Click(Sender: TObject);
begin
  PageControlMain.ActivePage := TabSheetRandom;
end;

procedure TFormMain.ButtonGroupMainMenuItems5Click(Sender: TObject);
begin
  PageControlMain.ActivePage := TabSheetAbout;
end;

procedure TFormMain.FormCreate(Sender: TObject);
begin
  CategoryButtons.SelectedItem := CategoryButtons.Categories[0].Items[0];
end;

end.
