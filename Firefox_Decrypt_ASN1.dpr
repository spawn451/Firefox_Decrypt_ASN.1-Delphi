program Firefox_Decrypt_ASN1;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  System.SysUtils,System.Classes,System.IniFiles,System.JSON,System.IOUtils,
  System.NetEncoding,Unit1;

type
  TOutputFormat = (ofHuman, ofJSON, ofCSV);

  TLoginData = record
    LoginURL: string;
    Username: string;
    Password: string;
    EncryptedUsername: TBytes;
    EncryptedPassword: TBytes;
    CreateDate: Int64;
  end;
  TLoginDataArray = array of TLoginData;

  TFirefoxProfile = record
    Name: string;
    Path: string;
  end;
  TFirefoxProfiles = array of TFirefoxProfile;

  TFirefoxDecryptor = class
  private
    FProfilePath: string;
    FOutputFormat: TOutputFormat;
    FMasterKeyHelper: TMasterKeyHelper;
    procedure OutputHuman(const Credentials: TLoginDataArray);
    procedure OutputJSON(const Credentials: TLoginDataArray);
    procedure OutputCSV(const Credentials: TLoginDataArray);
    procedure OutputCredentials(const Credentials: TLoginDataArray);
    function LoadFirefoxLoginData: TLoginDataArray;
  public
    constructor Create(const AProfilePath: string);
    destructor Destroy; override;
    procedure DecryptPasswords;
    property OutputFormat: TOutputFormat read FOutputFormat write FOutputFormat;
  end;

function GetFirefoxProfiles: TFirefoxProfiles;
var
  IniFile: TIniFile;
  IniPath: string;
  Sections: TStringList;
  i: Integer;
  ProfilePath: string;
begin
  SetLength(Result, 0);
  IniPath := TPath.Combine(GetEnvironmentVariable('APPDATA'),
    'Mozilla\Firefox\profiles.ini');

  if not FileExists(IniPath) then
  begin
    WriteLn('profiles.ini not found at: ', IniPath);
    Exit;
  end;

  Sections := TStringList.Create;
  IniFile := TIniFile.Create(IniPath);
  try
    IniFile.ReadSections(Sections);
    for i := 0 to Sections.Count - 1 do
    begin
      if Copy(Sections[i], 1, 7) = 'Profile' then
      begin
        ProfilePath := IniFile.ReadString(Sections[i], 'Path', '');
        if ProfilePath <> '' then
        begin
          SetLength(Result, Length(Result) + 1);
          Result[High(Result)].Name := ProfilePath;
          Result[High(Result)].Path := TPath.Combine(ExtractFilePath(IniPath),
            ProfilePath);
        end;
      end;
    end;
  finally
    IniFile.Free;
    Sections.Free;
  end;
end;

procedure ListProfiles;
var
  Profiles: TFirefoxProfiles;
  i: Integer;
begin
  Profiles := GetFirefoxProfiles;
  if Length(Profiles) = 0 then
  begin
    WriteLn('No Firefox profiles found.');
    Exit;
  end;

  WriteLn('Available Firefox profiles:');
  for i := 0 to High(Profiles) do
    WriteLn(i + 1, ' -> ', Profiles[i].Name);
end;

function SelectProfile(ProfileChoice: Integer = 0): string;
var
  Profiles: TFirefoxProfiles;
  input: string;
begin
  Result := '';
  Profiles := GetFirefoxProfiles;

  if Length(Profiles) = 0 then
  begin
    WriteLn('No Firefox profiles found.');
    Exit;
  end;

  if (ProfileChoice > 0) and (ProfileChoice <= Length(Profiles)) then
  begin
    Result := Profiles[ProfileChoice - 1].Path;
    Exit;
  end;

  WriteLn('Select the Mozilla profile you wish to decrypt:');
  for var i := 0 to High(Profiles) do
    WriteLn(i + 1, ' -> ', Profiles[i].Name);

  while True do
  begin
    Write('Profile number (1-', Length(Profiles), '): ');
    ReadLn(input);
    if TryStrToInt(input, ProfileChoice) and (ProfileChoice >= 1) and
      (ProfileChoice <= Length(Profiles)) then
    begin
      Result := Profiles[ProfileChoice - 1].Path;
      Break;
    end;
    WriteLn('Invalid selection. Please try again.');
  end;
end;

{ TFirefoxDecryptor }

constructor TFirefoxDecryptor.Create(const AProfilePath: string);
begin
  inherited Create;
  FProfilePath := AProfilePath;
  FMasterKeyHelper := TMasterKeyHelper.Create(AProfilePath);
  FOutputFormat := ofHuman;
end;

destructor TFirefoxDecryptor.Destroy;
begin
  FMasterKeyHelper.Free;
  inherited;
end;

procedure TFirefoxDecryptor.OutputHuman(const Credentials: TLoginDataArray);
begin
  for var i := 0 to Length(Credentials) - 1 do
  begin
    WriteLn;
    WriteLn('Website:   ', Credentials[i].LoginURL);
    WriteLn('Username: ''', Credentials[i].Username, '''');
    WriteLn('Password: ''', Credentials[i].Password, '''');
  end;
  WriteLn;
end;

procedure TFirefoxDecryptor.OutputJSON(const Credentials: TLoginDataArray);
var
  JSONArray: TJSONArray;
  JSONObject: TJSONObject;
begin
  JSONArray := TJSONArray.Create;
  try
    for var i := 0 to Length(Credentials) - 1 do
    begin
      JSONObject := TJSONObject.Create;
      JSONObject.AddPair('url', Credentials[i].LoginURL);
      JSONObject.AddPair('username', Credentials[i].Username);
      JSONObject.AddPair('password', Credentials[i].Password);
      JSONArray.AddElement(JSONObject);
    end;
    WriteLn(JSONArray.Format(2));
  finally
    JSONArray.Free;
  end;
end;

procedure TFirefoxDecryptor.OutputCSV(const Credentials: TLoginDataArray);
begin
  WriteLn('url;username;password');
  for var i := 0 to Length(Credentials) - 1 do
    WriteLn(Format('%s;%s;%s', [Credentials[i].LoginURL,
      Credentials[i].Username, Credentials[i].Password]));
end;

procedure TFirefoxDecryptor.OutputCredentials(const Credentials: TLoginDataArray);
begin
  case FOutputFormat of
    ofHuman: OutputHuman(Credentials);
    ofJSON:  OutputJSON(Credentials);
    ofCSV:   OutputCSV(Credentials);
  end;
end;

function TFirefoxDecryptor.LoadFirefoxLoginData: TLoginDataArray;
var
  JSONFile: string;
  JSONString: string;
  JSONValue: TJSONValue;
  JSONArray: TJSONArray;
begin
  SetLength(Result, 0);
  JSONFile := TPath.Combine(FProfilePath, 'logins.json');
  if not FileExists(JSONFile) then
    Exit;

  try
    JSONString := TFile.ReadAllText(JSONFile);
    JSONValue := TJSONObject.ParseJSONValue(JSONString);
    if not Assigned(JSONValue) then
      Exit;

    try
      if not(JSONValue is TJSONObject) then
        Exit;

      JSONArray := TJSONObject(JSONValue).GetValue<TJSONArray>('logins');
      if not Assigned(JSONArray) then
        Exit;

      SetLength(Result, JSONArray.Count);
      for var i := 0 to JSONArray.Count - 1 do
      begin
        with Result[i] do
        begin
          LoginURL := JSONArray.Items[i].GetValue<string>('formSubmitURL');
          EncryptedUsername := TNetEncoding.Base64.DecodeStringToBytes
            (JSONArray.Items[i].GetValue<string>('encryptedUsername'));
          EncryptedPassword := TNetEncoding.Base64.DecodeStringToBytes
            (JSONArray.Items[i].GetValue<string>('encryptedPassword'));
          CreateDate := JSONArray.Items[i].GetValue<Int64>
            ('timeCreated') div 1000;
        end;
      end;
    finally
      JSONValue.Free;
    end;
  except
    SetLength(Result, 0);
  end;
end;

procedure TFirefoxDecryptor.DecryptPasswords;
var
  Logins: TLoginDataArray;
  DecryptedLogins: TLoginDataArray;
  MasterKey: TBytes;
begin
  // Get master key
  WriteLn('Getting master key...');
  MasterKey := FMasterKeyHelper.GetMasterKey;
  WriteLn('Master key retrieved successfully!');

  // Load raw login data with encrypted values
  Logins := LoadFirefoxLoginData;
  WriteLn('Found ', Length(Logins), ' credentials');
  SetLength(DecryptedLogins, Length(Logins));

  // For each login entry:
  for var i := 0 to Length(Logins) - 1 do
  begin
    DecryptedLogins[i].LoginURL := Logins[i].LoginURL;
    WriteLn('Processing credential ', i + 1, ' of ', Length(Logins));

    try
      var UsernamePBE := NewASN1PBE(Logins[i].EncryptedUsername);
      DecryptedLogins[i].Username := TEncoding.UTF8.GetString(
        UsernamePBE.Decrypt(MasterKey)
      );
      WriteLn('Username decrypted successfully');
    except
      on E: Exception do
        WriteLn('Failed to decrypt username: ', E.Message);
    end;

    try
      var PasswordPBE := NewASN1PBE(Logins[i].EncryptedPassword);
      DecryptedLogins[i].Password := TEncoding.UTF8.GetString(
        PasswordPBE.Decrypt(MasterKey)
      );
      WriteLn('Password decrypted successfully');
    except
      on E: Exception do
        WriteLn('Failed to decrypt password: ', E.Message);
    end;
  end;

  OutputCredentials(DecryptedLogins);
end;

{ Main program }

procedure PrintUsage;
begin
  WriteLn('Firefox Password Decryptor');
  WriteLn('Usage: FirefoxDecrypt.exe [options]');
  WriteLn;
  WriteLn('Options:');
  WriteLn('  -f, --format FORMAT   Output format (human, json, csv)');
  WriteLn('  -l, --list           List available profiles');
  WriteLn('  -c, --choice NUMBER  Profile to use (starts with 1)');
  WriteLn('  -h, --help           Show this help message');
  WriteLn;
end;

var
  i: Integer;
  Param, Value: string;
  ListOnly: Boolean;
  ProfileChoice: Integer;
  ProfilePath: string;
  Decryptor: TFirefoxDecryptor;

begin
  try
    // Check for help flag first
    for i := 1 to ParamCount do
      if (ParamStr(i) = '-h') or (ParamStr(i) = '--help') then
      begin
        PrintUsage;
        Exit;
      end;

    ListOnly := False;
    ProfileChoice := 0;

    // Parse command line parameters
    i := 1;
    while i <= ParamCount do
    begin
      Param := ParamStr(i);

      if (Param = '-l') or (Param = '--list') then
        ListOnly := True
      else if (Param = '-c') or (Param = '--choice') then
      begin
        Inc(i);
        if i <= ParamCount then
          ProfileChoice := StrToIntDef(ParamStr(i), 0);
      end;

      Inc(i);
    end;

    if ListOnly then
    begin
      ListProfiles;
      Exit;
    end;

    // Get profile path
    ProfilePath := SelectProfile(ProfileChoice);
    if ProfilePath.IsEmpty then
    begin
      WriteLn('No profile selected or no profiles found.');
      Exit;
    end;

    // Create and initialize decryptor
    WriteLn('Initializing decryptor...');
    Decryptor := TFirefoxDecryptor.Create(ProfilePath);
    try
      // Parse output format if specified
      i := 1;
      while i <= ParamCount do
      begin
        Param := ParamStr(i);
        if (Param = '-f') or (Param = '--format') then
        begin
          Inc(i);
          if i <= ParamCount then
          begin
            Value := LowerCase(ParamStr(i));
            if Value = 'json' then
              Decryptor.OutputFormat := ofJSON
            else if Value = 'csv' then
              Decryptor.OutputFormat := ofCSV
            else
              Decryptor.OutputFormat := ofHuman;
          end;
        end;
        Inc(i);
      end;

      // Decrypt and output passwords
      Decryptor.DecryptPasswords;

    finally
      Decryptor.Free;
    end;

    WriteLn('Press Enter to exit...');
    ReadLn;

  except
    on E: Exception do
    begin
      WriteLn('Error: ', E.Message);
      WriteLn('Press Enter to exit...');
      ReadLn;
      ExitCode := 1;
    end;
  end;
end.
