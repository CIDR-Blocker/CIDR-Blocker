#pragma semicolon 1

#define PLUGIN_AUTHOR "Fishy"
#define PLUGIN_VERSION "1.0.0"

#include <sourcemod>

#pragma newdecls required
#pragma dynamic 1310720

Database hDB;

char Cache[5120][4][64]; //0:CIDR, 1:START, 2:END, 3:KICK_MESSAGE
char Whitelist[512][2][32]; //0:Type (steam, ip), 1:Identity

int CacheRowCount;
int WhitelistRowCount;

bool CacheLoaded;
bool WhitelistLoaded;
bool Log;

ConVar cLog;

public Plugin myinfo = 
{
	name = "CIDR Blocker",
	author = PLUGIN_AUTHOR,
	description = "Blocks CIDR (Classless Inter-Domain Routing) IP Ranges",
	version = PLUGIN_VERSION,
	url = "https://keybase.io/rumblefrog"
};

public APLRes AskPluginLoad2(Handle myself, bool late, char[] error, int err_max)
{
	hDB = SQL_Connect("cidr_blocker", true, error, err_max);
	
	if (hDB == INVALID_HANDLE)
		return APLRes_Failure;
	
	char ListCreateSQL[] = "CREATE TABLE IF NOT EXISTS `cidr_list` ( `id` INT NOT NULL AUTO_INCREMENT , `cidr` VARCHAR(32) NOT NULL , `kick_message` VARCHAR(64) NOT NULL DEFAULT 'IP BLOCKED' , `comment` VARCHAR(255) NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;";
	char WhitelistCreateSQL[] = "CREATE TABLE IF NOT EXISTS `cidr_whitelist` ( `id` INT NOT NULL AUTO_INCREMENT , `type` ENUM('steam','ip') NOT NULL , `identity` VARCHAR(32) NOT NULL , `comment` VARCHAR(255) NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;";
	char LogCreateSQL[] = "CREATE TABLE IF NOT EXISTS `cidr_log` ( `id` INT NOT NULL AUTO_INCREMENT , `ip` VARBINARY(16) NOT NULL , `steamid` VARCHAR(32) NOT NULL , `name` VARCHAR(64) NOT NULL , `cidr` VARCHAR(32) NOT NULL , `time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP , PRIMARY KEY (`id`), INDEX (`steamid`), INDEX (`ip`), INDEX (`cidr`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;";
	
	SQL_SetCharset(hDB, "utf8mb4");
			
	hDB.Query(OnTableCreate, ListCreateSQL);
	hDB.Query(OnTableCreate, WhitelistCreateSQL);
	hDB.Query(OnTableCreate, LogCreateSQL);
	
	RegPluginLibrary("CIDR_Blocker");

	return APLRes_Success;
}

public void OnTableCreate(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
		SetFailState("Unable to create table: %s", error);
}

public void OnPluginStart()
{
	CreateConVar("sm_cidr_version", PLUGIN_VERSION, "CIDR Blocker Version", FCVAR_REPLICATED | FCVAR_SPONLY | FCVAR_DONTRECORD | FCVAR_NOTIFY);
	
	cLog = CreateConVar("sm_cidr_log", "1", "Enable blocked logging", FCVAR_NONE, true, 0.0, true, 1.0);
	
	Log = cLog.BoolValue;
	cLog.AddChangeHook(OnLogChange);
	
	RegAdminCmd("sm_cidr_whitelist", CmdWhitelist, ADMFLAG_CHEATS);
	
	LoadToCache();
	LoadToWhitelist();
}

public void OnLogChange(ConVar convar, const char[] oldValue, const char[] newValue)
{
	Log = cLog.BoolValue;
}

void LoadToCache()
{
	char Select_Query[512];
	
	Format(Select_Query, sizeof Select_Query, "SELECT `cidr`, `kick_message` FROM `cidr_list`");
	
	hDB.Query(SQL_OnLoadToCache, Select_Query);
}

void LoadToWhitelist()
{
	char Select_Query[512];
	
	Format(Select_Query, sizeof Select_Query, "SELECT `type`, `identity` FROM `cidr_whitelist`");
	
	hDB.Query(SQL_OnLoadToWhitelist, Select_Query);
}

public void SQL_OnLoadToCache(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
		SetFailState("Failed to fetch cache: %s", error); 
		
	CacheRowCount = results.RowCount;
	
	for (int i = 1; i <= CacheRowCount; i++)
	{
		results.FetchRow();
		
		results.FetchString(0, Cache[i][0], sizeof Cache[][]); //CIDR
		results.FetchString(1, Cache[i][3], sizeof Cache[][]); //KICK_MESSAGE
		
		int iStart, iEnd;
		
		ParseCIDR(Cache[i][0], iStart, iEnd);
		
		IntToString(iStart, Cache[i][1], sizeof Cache[][]); //START
		IntToString(iEnd, Cache[i][2], sizeof Cache[][]); //END
	}
	
	CacheLoaded = true;
}

public void SQL_OnLoadToWhitelist(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
		SetFailState("Failed to fetch whitelist: %s", error); 
		
	WhitelistRowCount = results.RowCount;
	
	for (int i = 1; i <= WhitelistRowCount; i++)
	{
		results.FetchRow();
		
		results.FetchString(0, Whitelist[i][0], sizeof Whitelist[][]); //TYPE
		results.FetchString(1, Whitelist[i][1], sizeof Whitelist[][]); //IDENTITY
	}
	
	WhitelistLoaded = true;
}

public void OnClientPostAdminCheck(int client)
{
	if (!CacheLoaded || !WhitelistLoaded)
		return;
	
	if (!IsInWhitelist(client))
	{
		char IP[32];
		
		GetClientIP(client, IP, sizeof IP);
		
		int ID;
		
		if ((ID = IsInRange(IP)) != -1)
		{
			LogReject(client, ID);
			KickClient(client, Cache[ID][3]);
		}
	}
}

public Action CmdWhitelist(int client, int args)
{
	if (args < 1)
	{
		ReplyToCommand(client, "sm_cidir_whitelist <steamid/ip> <comment>");
		return Plugin_Handled;
	}
	
	char ID[32], Comment[255], sArg[255], Insert_Query[1024], Escaped_Comment[511], Type[32];
	
	GetCmdArg(1, ID, sizeof ID);
	
	for (int i = 2; i <= args; i++)
	{
		GetCmdArg(i, sArg, sizeof sArg);
		Format(Comment, sizeof Comment, "%s %s", Comment, sArg);
	}
	
	if (StrContains(ID, ".") != -1)
		Type = "ip";
	else
		Type = "steam";
		
	hDB.Escape(Comment, Escaped_Comment, sizeof Escaped_Comment);
	
	Format(Insert_Query, sizeof Insert_Query, "INSERT INTO `cidr_whitelist` (`type`, `identity`, `comment`) VALUES ('%s', '%s', '%s')", Type, ID, Escaped_Comment);
	
	hDB.Query(SQL_OnCmdWhitelist, Insert_Query);
	
	return Plugin_Handled;
}

public void SQL_OnCmdWhitelist(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
	{
		LogError("Failed to insert whitelist: %s", error); 
		return;
	}
	
	LoadToWhitelist();
}

void LogReject(int client, int ID)
{
	if (!Log) return;
	
	char Insert_Query[512], Name[32], Escaped_Name[65], IP[32], SteamID[32];
	
	GetClientName(client, Name, sizeof Name);
	GetClientIP(client, IP, sizeof IP);
	GetClientAuthId(client, AuthId_Steam2, SteamID, sizeof SteamID);
	
	hDB.Escape(Name, Escaped_Name, sizeof Escaped_Name);
	
	Format(Insert_Query, sizeof Insert_Query, "INSERT INTO `cidr_log` (`ip`, `steamid`, `name`, `cidr`) VALUES ('%s', '%s', '%s', '%s')", IP, SteamID, Escaped_Name, Cache[ID][0]);
	
	hDB.Query(SQL_OnLogReject, Insert_Query);
}

public void SQL_OnLogReject(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
		LogError("Failed to insert log: %s", error); 
}

bool IsInWhitelist(int client)
{
	char SteamID[32], IP[32];
	
	GetClientAuthId(client, AuthId_Steam2, SteamID, sizeof SteamID);
	GetClientIP(client, IP, sizeof IP);
	
	for (int i = 1; i <= WhitelistRowCount; i++)
	{
		if (StrEqual(Whitelist[i][0], "steam"))
		{
			return StrEqual(Whitelist[i][1], SteamID);
		}
		
		if (StrEqual(Whitelist[i][0], "ip"))
		{
			return StrEqual(Whitelist[i][1], IP);
		}
	}
	
	return false;
}

int IsInRange(const char[] IP)
{
	int iNet = NetAddr2Long(IP), iStart, iEnd;
	
	for (int i = 1; i <= CacheRowCount; i++)
	{
		iStart = StringToInt(Cache[i][1]);
		iEnd = StringToInt(Cache[i][2]);
		
		if (iStart <= iNet && iNet <= iEnd)
			return i;
	}
	
	return -1;
}

stock void ParseCIDR(const char[] sCIDR, int &iStart, int &iEnd)
{
    char Pieces[2][32];
    
    ExplodeString(sCIDR, "/", Pieces, sizeof Pieces, sizeof Pieces[]);
    int baseip = NetAddr2Long(Pieces[0]);
    int prefix = StringToInt(Pieces[1]);
    
    if(prefix == 0) {
        LogError("CIDR prefix 0, clamping to 32. %s", sCIDR);
        prefix = 32;
    }
    
    int shift = 32 - prefix;
    int mask = (1 << shift) - 1;
    int start = baseip >> shift << shift;
    int end = start | mask;
    
    iStart = start;
    iEnd = end;
}

stock int NetAddr2Long(const char[] ip)
{
    char Pieces[4][16];
    int nums[4];

    if (ExplodeString(ip, ".", Pieces, sizeof Pieces, sizeof Pieces[]) != 4)
        return 0;
    
    nums[0] = StringToInt(Pieces[0]);
    nums[1] = StringToInt(Pieces[1]);
    nums[2] = StringToInt(Pieces[2]);
    nums[3] = StringToInt(Pieces[3]);

    return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]);
}