object RandomCompareForm: TRandomCompareForm
  Left = 0
  Top = 0
  Caption = 'Random Number Generator Comparison'
  ClientHeight = 469
  ClientWidth = 622
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  DesignSize = (
    622
    469)
  TextHeight = 15
  object Label1: TLabel
    Left = 16
    Top = 16
    Width = 59
    Height = 15
    Caption = 'Repetitions'
  end
  object Label2: TLabel
    Left = 256
    Top = 16
    Width = 24
    Height = 15
    Caption = 'x256'
  end
  object EditRepetitions: TEdit
    Left = 120
    Top = 13
    Width = 121
    Height = 23
    NumbersOnly = True
    TabOrder = 0
    Text = '1000'
  end
  object Chart1: TChart
    Left = 0
    Top = 42
    Width = 625
    Height = 427
    Legend.Alignment = laBottom
    Legend.CheckBoxes = True
    Legend.LegendStyle = lsSeries
    Title.Text.Strings = (
      'Comparison of random number generators')
    BottomAxis.Automatic = False
    BottomAxis.AutomaticMaximum = False
    BottomAxis.AutomaticMinimum = False
    BottomAxis.LabelsAngle = 90
    BottomAxis.Maximum = 256.000000000000000000
    BottomAxis.Title.Caption = 'Values'
    LeftAxis.Title.Caption = 'Occurances'
    TopAxis.Title.Caption = 'Value'
    View3D = False
    TabOrder = 1
    Anchors = [akLeft, akTop, akRight, akBottom]
    ExplicitHeight = 399
    DefaultCanvas = 'TGDIPlusCanvas'
    ColorPaletteIndex = 13
    object Series1: TLineSeries
      HoverElement = [heCurrent]
      Legend.Text = 'DEC'
      LegendTitle = 'DEC'
      Brush.BackColor = clDefault
      Pointer.InflateMargins = True
      Pointer.Style = psRectangle
      XValues.Name = 'X'
      XValues.Order = loAscending
      YValues.Name = 'Y'
      YValues.Order = loNone
    end
    object Series2: TLineSeries
      HoverElement = [heCurrent]
      Legend.Text = 'Delphi RTL'
      LegendTitle = 'Delphi RTL'
      Brush.BackColor = clDefault
      Pointer.InflateMargins = True
      Pointer.Style = psRectangle
      XValues.Name = 'X'
      XValues.Order = loAscending
      YValues.Name = 'Y'
      YValues.Order = loNone
    end
  end
  object ButtonStart: TButton
    Left = 296
    Top = 11
    Width = 75
    Height = 25
    Caption = '&Start'
    TabOrder = 2
    OnClick = ButtonStartClick
  end
end
