/*
CIDR Blocker - Blocks CIDR (Classless Inter-Domain Routing) IP Ranges
Copyright (C) 2017  RumbleFrog

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma semicolon 1

#define PLUGIN_AUTHOR "Fishy"
#define PLUGIN_VERSION "1.1.7"

#define LIST_CREATE_SQL "CREATE TABLE IF NOT EXISTS `cidr_list` ( `id` INT NOT NULL AUTO_INCREMENT , `cidr` VARCHAR(32) NOT NULL UNIQUE , `kick_message` VARCHAR(64) NOT NULL DEFAULT 'IP BLOCKED' , `comment` VARCHAR(255) NULL , PRIMARY KEY (`id`), INDEX (`cidr`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;"
#define WHITELIST_CREATE_SQL "CREATE TABLE IF NOT EXISTS `cidr_whitelist` ( `id` INT NOT NULL AUTO_INCREMENT , `type` ENUM('steam','ip') NOT NULL , `identity` VARCHAR(32) NOT NULL , `comment` VARCHAR(255) NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;"
#define LOG_CREATE_SQL "CREATE TABLE IF NOT EXISTS `cidr_log` ( `id` INT NOT NULL AUTO_INCREMENT , `ip` VARBINARY(16) NOT NULL , `steamid` VARCHAR(32) NOT NULL , `name` VARCHAR(64) NOT NULL , `cidr` VARCHAR(32) NOT NULL , `time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP , PRIMARY KEY (`id`), INDEX (`steamid`), INDEX (`ip`), INDEX (`cidr`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;"

#include <sourcemod>

#pragma newdecls required

Database hDB;

enum WhitelistType {
	WhitelistSteam,
	WhitelistIP,
	WhitelistInvalid,
}

enum struct WhitelistEntry {
	WhitelistType type;

	char identity[32];
}

ArrayList Whitelist;

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
	RegPluginLibrary("cidr_blocker");

	return APLRes_Success;
}

public void OnPluginStart()
{
	Database.Connect(SQL_OnDatabaseConnect, "cidr_blocker");

	CreateConVar("sm_cidr_version", PLUGIN_VERSION, "CIDR Blocker Version", FCVAR_REPLICATED | FCVAR_SPONLY | FCVAR_DONTRECORD | FCVAR_NOTIFY);
	
	cLog = CreateConVar("sm_cidr_log", "1", "Enable blocked logging", FCVAR_NONE, true, 0.0, true, 1.0);
	
	Log = cLog.BoolValue;
	cLog.AddChangeHook(OnLogChange);
	
	RegAdminCmd("sm_cidr_whitelist", CmdWhitelist, ADMFLAG_CHEATS);

	Whitelist = new ArrayList(sizeof(WhitelistEntry));
}

public void SQL_OnDatabaseConnect(Database db, const char[] error, any data)
{
	if (db == null)
		SetFailState("Database connection failure: %s", error);

	hDB = db;

	hDB.SetCharset("utf8mb4");

	hDB.Query(SQL_OnCreateTable, LIST_CREATE_SQL);
	hDB.Query(SQL_OnCreateTable, WHITELIST_CREATE_SQL);
	hDB.Query(SQL_OnCreateTable, LOG_CREATE_SQL);

	hDB.Query(SQL_OnLoadToWhitelist, "SELECT `type`, `identity` FROM `cidr_whitelist`");
}

public void SQL_OnCreateTable(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
		SetFailState("Unable to create table: %s", error);
}

public void OnLogChange(ConVar convar, const char[] oldValue, const char[] newValue)
{
	Log = cLog.BoolValue;
}

public void SQL_OnLoadToWhitelist(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
		SetFailState("Failed to fetch whitelist: %s", error); 

	char type[32];

	WhitelistEntry w_temp;
	
	for (int i = 1; i <= results.RowCount; i++)
	{
		results.FetchRow();
		
		results.FetchString(0, type, sizeof(type));
		results.FetchString(1, w_temp.identity, sizeof(WhitelistEntry::identity));

		w_temp.type = ToWhitelistType(type);

		Whitelist.PushArray(w_temp);
	}
}

WhitelistType ToWhitelistType(const char[] type)
{
	if (StrEqual(type, "steam"))
		return WhitelistSteam;

	if (StrEqual(type, "ip"))
		return WhitelistIP;

	return WhitelistInvalid;
}

public void OnClientPostAdminCheck(int client)
{		
	if (!IsClientConnected(client))
		return;
	
	if (!IsInWhitelist(client))
	{
		char IP[32], Select_Query[512];
		
		GetClientIP(client, IP, sizeof IP);
		
		Format(Select_Query, sizeof Select_Query, "SELECT `cidr`, `kick_message` FROM cidr_list WHERE INET_ATON('%s') BETWEEN (INET_ATON(SUBSTRING_INDEX(`cidr`, '/', 1)) & 0xffffffff ^ ((0x1 << ( 32 - SUBSTRING_INDEX(`cidr`, '/', -1))  ) -1 )) AND (INET_ATON(SUBSTRING_INDEX(`cidr`, '/', 1)) | ((0x100000000 >> SUBSTRING_INDEX(`cidr`, '/', -1) ) -1 )) LIMIT 1", IP);
		
		hDB.Query(SQL_OnCIDRFetch, Select_Query, client);
	}
}

public void SQL_OnCIDRFetch(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
	{
		LogError("Failed to fetch CIDR: %s", error); 
		return;
	}
	
	if (results.RowCount > 0)
	{
		char CIDR[32], Kick_Message[64];
		
		results.FetchRow();

		results.FetchString(0, CIDR, sizeof CIDR);
		results.FetchString(1, Kick_Message, sizeof Kick_Message);
		
		LogReject(pData, CIDR);
		KickClient(pData, Kick_Message);
	}
}

public Action CmdWhitelist(int client, int args)
{
	if (args < 1)
	{
		ReplyToCommand(client, "sm_cidr_whitelist <steamid/ip> <comment>");
		return Plugin_Handled;
	}
	
	char ID[32], Comment[255], sArg[255], Insert_Query[1024], Type[32];
	
	GetCmdArg(1, ID, sizeof ID);
	
	for (int i = 2; i <= args; i++)
	{
		GetCmdArg(i, sArg, sizeof sArg);
		Format(Comment, sizeof Comment, "%s %s", Comment, sArg);
	}
		
	Type = (StrContains(ID, ".") != -1) ? "ip" : "steam";
	
	hDB.Format(Insert_Query, sizeof Insert_Query, "INSERT INTO `cidr_whitelist` (`type`, `identity`, `comment`) VALUES (%s, %s, %s)", Type, ID, Comment);
	
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
}

void LogReject(int client, const char[] CIDR)
{
	if (!Log) return;
	
	char Insert_Query[512], Name[32], IP[32], SteamID[32];
	
	GetClientName(client, Name, sizeof Name);
	GetClientIP(client, IP, sizeof IP);
	GetClientAuthId(client, AuthId_Steam2, SteamID, sizeof SteamID);
	
	hDB.Format(Insert_Query, sizeof Insert_Query, "INSERT INTO `cidr_log` (`ip`, `steamid`, `name`, `cidr`) VALUES (%s, %s, %s, %s'", IP, SteamID, Name, CIDR);
	
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

	// In-memory whitelist is designed for small-case scenarios
	// For large cases, refer to the forward for determining action upon result

	WhitelistEntry entry;

	for (int i = 0; i < Whitelist.Length; i += 1)
	{
		Whitelist.GetArray(i, entry);

		if (entry.type == WhitelistSteam && StrEqual(entry.identity, SteamID))
			return true;

		if (entry.type == WhitelistIP && StrEqual(entry.identity, IP))
			return true;
	}
	
	return false;
}
