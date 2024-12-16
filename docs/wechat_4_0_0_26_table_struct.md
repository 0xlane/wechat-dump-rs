# 微信4.0数据库结构

> 基于微信 4.0.0.26

## login

用户登录相关

### key_info.db

用户认证信息相关

```sql
CREATE TABLE LoginKeyInfoTable(user_name_md5 TEXT, key_md5 TEXT, key_info_md5 TEXT, key_info_data BLOB)
CREATE UNIQUE INDEX LoginKeyInfoTable_USER_KEYINFO ON LoginKeyInfoTable(user_name_md5, key_info_md5)
```

## biz

公众号相关

### biz.db

```sql
CREATE TABLE biz_pay_status(url_id TEXT, is_charge_appmsg INTEGER, is_paid INTEGER, friend_pay_count_str TEXT)
```

## contact

联系人相关

### contact.db

联系人数据库，包括在微信里你能看到的各种群、群成员、通讯录、公众号的信息。

```sql
CREATE TABLE biz_info(id INTEGER PRIMARY KEY, username TEXT, type INTEGER, accept_type INTEGER, child_type INTEGER, version INTEGER, external_info TEXT, brand_info TEXT, brand_icon_url TEXT, brand_list TEXT, brand_flag INTEGER, belong TEXT, ext_buffer BLOB)
CREATE TABLE biz_profile(username TEXT, service_type INTEGER, article_count INTEGER, friend_sub_count INTEGER, is_subscribe INTEGER, offset TEXT, time_stamp INTEGER, is_end INTEGER, resp_buffer BLOB)
CREATE TABLE biz_session_feeds(username TEXT, showname TEXT, desc TEXT, type INTEGER, unread_count INTEGER, update_time INTEGER, create_time INTEGER, biz_attr_version INTEGER)
CREATE TABLE chat_room(id INTEGER PRIMARY KEY, username TEXT, owner TEXT, ext_buffer BLOB)
CREATE TABLE chat_room_info_detail(room_id_ INTEGER PRIMARY KEY, username_ TEXT, announcement_ TEXT, announcement_editor_ TEXT, announcement_publish_time_ INTEGER, chat_room_status_ INTEGER, room_top_msg_closed_id_list_text_ TEXT, xml_announcement_ TEXT, ext_buffer_ BLOB)
CREATE TABLE chatroom_member(room_id INTEGER, member_id INTEGER, CONSTRAINT room_member UNIQUE(room_id, member_id))
CREATE TABLE contact(id INTEGER PRIMARY KEY, username TEXT, local_type INTEGER, alias TEXT, encrypt_username TEXT, flag INTEGER, delete_flag INTEGER, verify_flag INTEGER, remark TEXT, remark_quan_pin TEXT, remark_pin_yin_initial TEXT, nick_name TEXT, pin_yin_initial TEXT, quan_pin TEXT, big_head_url TEXT, small_head_url TEXT, head_img_md5 TEXT, chat_room_notify INTEGER, is_in_chat_room INTEGER, description TEXT, extra_buffer BLOB, chat_room_type INTEGER)
CREATE TABLE contact_label(label_id_ INTEGER PRIMARY KEY, label_name_ TEXT, sort_order_ INTEGER)
CREATE TABLE encrypt_name2id(username TEXT PRIMARY KEY)
CREATE TABLE name2id(username TEXT PRIMARY KEY)
CREATE TABLE openim_acct_type(lang_id INTEGER, acc_type_id TEXT, update_time INTEGER, ext_buffer BLOB, CONSTRAINT accTypeId_langId PRIMARY KEY(acc_type_id, lang_id))
CREATE TABLE openim_appid(lang_id INTEGER, app_id TEXT, acct_type_id TEXT, update_time INTEGER, ext_buffer BLOB, CONSTRAINT appId_langId PRIMARY KEY(app_id, lang_id))
CREATE TABLE openim_wording(lang_id INTEGER, app_id TEXT, wording_id TEXT, wording TEXT, pinyin TEXT, quan_pin TEXT, update_time INTEGER, ext_buffer BLOB, CONSTRAINT appId_langId_wordingId PRIMARY KEY(app_id, lang_id, wording_id))
CREATE TABLE oplog(id INTEGER PRIMARY KEY ASC AUTOINCREMENT, buffer BLOB)
CREATE TABLE sqlite_sequence(name,seq)
CREATE TABLE stranger(id INTEGER PRIMARY KEY, username TEXT, local_type INTEGER, alias TEXT, encrypt_username TEXT, flag INTEGER, delete_flag INTEGER, verify_flag INTEGER, remark TEXT, remark_quan_pin TEXT, remark_pin_yin_initial TEXT, nick_name TEXT, pin_yin_initial TEXT, quan_pin TEXT, big_head_url TEXT, small_head_url TEXT, head_img_md5 TEXT, chat_room_notify INTEGER, is_in_chat_room INTEGER, description TEXT, extra_buffer BLOB, chat_room_type INTEGER)
CREATE TABLE stranger_ticket_info(id INTEGER PRIMARY KEY, ticket TEXT)
CREATE TABLE ticket_info(id INTEGER PRIMARY KEY, ticket TEXT)
CREATE INDEX biz_profile_time ON biz_profile(time_stamp)
CREATE UNIQUE INDEX biz_session_feeds_username ON biz_session_feeds(username)
CREATE INDEX chatroom_member_member_id ON chatroom_member(member_id)
CREATE INDEX chatroom_member_room_id ON chatroom_member(room_id)
CREATE INDEX contact_localType ON contact(local_type)
CREATE INDEX stranger_localType ON stranger(local_type)
```

### contact_fts.db

```sql
CREATE VIRTUAL TABLE chatroom_member_fts_v3 USING fts5(tokenize = 'MMFtsTokenizer disable_pinyin enable_special_char', a_group_remark, room_id UNINDEXED, member_id UNINDEXED)
CREATE TABLE chatroom_member_fts_v3_aux(room_id INTEGER, member_id INTEGER, CONSTRAINT room_member UNIQUE(room_id, member_id))
CREATE TABLE 'chatroom_member_fts_v3_config'(k PRIMARY KEY, v) WITHOUT ROWID
CREATE TABLE 'chatroom_member_fts_v3_content'(id INTEGER PRIMARY KEY, c0, c1, c2)
CREATE TABLE 'chatroom_member_fts_v3_data'(id INTEGER PRIMARY KEY, block BLOB)
CREATE TABLE 'chatroom_member_fts_v3_docsize'(id INTEGER PRIMARY KEY, sz BLOB)
CREATE TABLE 'chatroom_member_fts_v3_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID
CREATE VIRTUAL TABLE contact_fts_pinyin_v1 USING fts5(tokenize = 'MMFtsTokenizer disable_origin', content='contact_fts_v1', search_key, local_type UNINDEXED)
CREATE TABLE 'contact_fts_pinyin_v1_config'(k PRIMARY KEY, v) WITHOUT ROWID
CREATE TABLE 'contact_fts_pinyin_v1_data'(id INTEGER PRIMARY KEY, block BLOB)
CREATE TABLE 'contact_fts_pinyin_v1_docsize'(id INTEGER PRIMARY KEY, sz BLOB)
CREATE TABLE 'contact_fts_pinyin_v1_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID
CREATE VIRTUAL TABLE contact_fts_v1 USING fts5(tokenize = 'MMFtsTokenizer disable_pinyin enable_special_char', search_key, local_type UNINDEXED)
CREATE TABLE 'contact_fts_v1_config'(k PRIMARY KEY, v) WITHOUT ROWID
CREATE TABLE 'contact_fts_v1_content'(id INTEGER PRIMARY KEY, c0, c1)
CREATE TABLE 'contact_fts_v1_data'(id INTEGER PRIMARY KEY, block BLOB)
CREATE TABLE 'contact_fts_v1_docsize'(id INTEGER PRIMARY KEY, sz BLOB)
CREATE TABLE 'contact_fts_v1_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID
CREATE TABLE db_info(Key TEXT PRIMARY KEY, ValueInt64 INTEGER, ValueDouble REAL, ValueStdStr TEXT, ValueBlob BLOB)
CREATE TABLE name2id(username TEXT PRIMARY KEY)
CREATE INDEX chatroom_member_fts_v3_aux_member_id ON chatroom_member_fts_v3_aux(member_id)
CREATE INDEX chatroom_member_fts_v3_aux_room_id ON chatroom_member_fts_v3_aux(room_id)
```

### fmessage_new.db

```sql
CREATE TABLE FMessageTable(user_name_ TEXT, type_ INTEGER, timestamp_ INTEGER, encrypt_user_name_ TEXT, content_ TEXT, is_sender_ INTEGER, ticket_ TEXT, scene_ INTEGER, fmessage_detail_buf_ TEXT)
CREATE INDEX FMessageTable_TYPE_TIME ON FMessageTable(type_, timestamp_)
```

### wa_contact_new.db

```sql
CREATE TABLE WeAppBizAttrSyncBufferTableV02(user_name TEXT PRIMARY KEY, last_update_time INTEGER, version TEXT)
CREATE TABLE wacontact(user_name TEXT PRIMARY KEY, type INTEGER, brand_icon_url TEXT, external_info TEXT, contact_pack_data BLOB, wx_app_opt INTEGER, head_image_status TEXT, app_id TEXT)
CREATE INDEX wacontact_APPID ON wacontact(app_id)
```

## emoticon

表情包相关

### emoticon.db

```sql
CREATE TABLE kCustomEmoticonOrderTable(md5 TEXT)
CREATE TABLE kFavEmoticonOrderTable(md5 TEXT)
CREATE TABLE kNonStoreEmoticonTable(type INTEGER, md5 TEXT, caption TEXT, product_id TEXT, aes_key TEXT, thumb_url TEXT, tp_url TEXT, auth_key TEXT, cdn_url TEXT, extern_url TEXT, extern_md5 TEXT, encrypt_url TEXT)
CREATE TABLE kStoreEmoticonCaptionsTable(package_id_ TEXT, md5_ TEXT, language_ TEXT, caption_ TEXT)
CREATE TABLE kStoreEmoticonFilesTable(package_id_ TEXT, md5_ TEXT, type_ INTEGER, sort_order_ INTEGER, emoticon_size_ INTEGER, emoticon_offset_ INTEGER, thumb_size_ INTEGER, thumb_offset_ INTEGER)
CREATE TABLE kStoreEmoticonPackageTable(package_id_ TEXT, package_name_ TEXT, payment_status_ INTEGER, download_status_ INTEGER, install_time_ INTEGER, remove_time_ INTEGER, sort_order_ INTEGER, introduction_ TEXT, full_description_ TEXT, copyright_ TEXT, author_ TEXT, store_icon_url_ TEXT, panel_url_ TEXT)
CREATE UNIQUE INDEX kCustomEmoticonOrderTable_MD5 ON kCustomEmoticonOrderTable(md5)
CREATE UNIQUE INDEX kFavEmoticonOrderTable_MD5 ON kFavEmoticonOrderTable(md5)
CREATE UNIQUE INDEX kNonStoreEmoticonTable_TYPE_MD5 ON kNonStoreEmoticonTable(type, md5)
CREATE INDEX kStoreEmoticonCaptionsTable_MD5 ON kStoreEmoticonCaptionsTable(md5_)
CREATE UNIQUE INDEX kStoreEmoticonCaptionsTable_PID_MD5_LAN ON kStoreEmoticonCaptionsTable(package_id_, md5_, language_)
CREATE INDEX kStoreEmoticonFilesTable_MD5 ON kStoreEmoticonFilesTable(md5_)
CREATE UNIQUE INDEX kStoreEmoticonFilesTable_PID_MD5 ON kStoreEmoticonFilesTable(package_id_, md5_)
CREATE UNIQUE INDEX kStoreEmoticonPackageTable_PID ON kStoreEmoticonPackageTable(package_id_)
```

## favorite

收藏

### favorite.db

```sql
CREATE TABLE buff(Key TEXT PRIMARY KEY, ValueInt64 INTEGER, ValueDouble REAL, ValueStdStr TEXT, ValueBlob BLOB)
CREATE TABLE config(Key TEXT PRIMARY KEY, ValueInt64 INTEGER, ValueDouble REAL, ValueStdStr TEXT, ValueBlob BLOB)
CREATE TABLE fav_bind_tag_db_item(tag_local_id INTEGER, tag_server_id INTEGER, fav_local_id INTEGER, fav_server_id INTEGER, op_code INTEGER)
CREATE TABLE fav_db_item(local_id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, type INTEGER, update_seq INTEGER, flag INTEGER, update_time INTEGER, version INTEGER, content TEXT, source_id TEXT, sync_status INTEGER, upload_status INTEGER, fromusr TEXT, fromusr_id INTEGER, realchatname TEXT, realchatname_id INTEGER, ext_buf TEXT)
CREATE TABLE fav_tag_db_item(local_id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, name TEXT, seq INTEGER)
CREATE TABLE sqlite_sequence(name,seq)
CREATE INDEX fav_bind_tag_db_item_FAVLOCALID ON fav_bind_tag_db_item(fav_local_id)
CREATE INDEX fav_bind_tag_db_item_FAVSERVERID ON fav_bind_tag_db_item(fav_server_id)
CREATE INDEX fav_bind_tag_db_item_OPCODE ON fav_bind_tag_db_item(op_code)
CREATE INDEX fav_bind_tag_db_item_TAGLOCALID ON fav_bind_tag_db_item(tag_local_id)
CREATE INDEX fav_bind_tag_db_item_TAGSERVERID ON fav_bind_tag_db_item(tag_server_id)
CREATE INDEX fav_db_item_FROMUSR_ID ON fav_db_item(fromusr_id)
CREATE INDEX fav_db_item_REALCHATNAME_ID ON fav_db_item(realchatname_id)
CREATE INDEX fav_db_item_SERVERID ON fav_db_item(server_id)
CREATE INDEX fav_db_item_SOURCEID ON fav_db_item(source_id)
CREATE INDEX fav_db_item_SYNC_STATUS ON fav_db_item(sync_status)
CREATE INDEX fav_db_item_TYPE ON fav_db_item(type)
CREATE INDEX fav_db_item_UPDATE_TIME ON fav_db_item(update_time)
CREATE INDEX fav_db_item_UPLOAD_STATUS ON fav_db_item(upload_status)
CREATE INDEX fav_tag_db_item_SERVERID ON fav_tag_db_item(server_id)
```

### favorite_fts.db

```sql
CREATE VIRTUAL TABLE fav_fts_v1 USING fts5(tokenize = 'MMFtsTokenizer disable_pinyin', content, local_id UNINDEXED, update_time UNINDEXED, type UNINDEXED)
CREATE TABLE 'fav_fts_v1_config'(k PRIMARY KEY, v) WITHOUT ROWID
CREATE TABLE 'fav_fts_v1_content'(id INTEGER PRIMARY KEY, c0, c1, c2, c3)
CREATE TABLE 'fav_fts_v1_data'(id INTEGER PRIMARY KEY, block BLOB)
CREATE TABLE 'fav_fts_v1_docsize'(id INTEGER PRIMARY KEY, sz BLOB)
CREATE TABLE 'fav_fts_v1_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID
CREATE TABLE table_info(Key TEXT PRIMARY KEY, ValueInt64 INTEGER, ValueDouble REAL, ValueStdStr TEXT, ValueBlob BLOB)
```

## hardlink

### hardlink.db

```sql
CREATE TABLE db_info(Key TEXT PRIMARY KEY, ValueInt64 INTEGER, ValueDouble REAL, ValueStdStr TEXT, ValueBlob BLOB)
CREATE TABLE dir2id(username TEXT PRIMARY KEY)
CREATE TABLE file_checkpoint_v3(month_id INTEGER PRIMARY KEY ASC)
CREATE TABLE file_hardlink_info_v3(md5_hash INTEGER, md5 TEXT, type INTEGER, file_name TEXT, file_size INTEGER, modify_time INTEGER, dir1 INTEGER, dir2 INTEGER, _rowid_ INTEGER PRIMARY KEY ASC, extra_buffer BLOB)
CREATE TABLE image_hardlink_info_v3(md5_hash INTEGER, md5 TEXT, type INTEGER, file_name TEXT, file_size INTEGER, modify_time INTEGER, dir1 INTEGER, dir2 INTEGER, _rowid_ INTEGER PRIMARY KEY ASC, extra_buffer BLOB)
CREATE TABLE talker_checkpoint_v3(talker_id INTEGER PRIMARY KEY ASC, month_id INTEGER)
CREATE TABLE video_checkpoint_v3(month_id INTEGER PRIMARY KEY ASC)
CREATE TABLE video_hardlink_info_v3(md5_hash INTEGER, md5 TEXT, type INTEGER, file_name TEXT, file_size INTEGER, modify_time INTEGER, dir1 INTEGER, dir2 INTEGER, _rowid_ INTEGER PRIMARY KEY ASC, extra_buffer BLOB)
CREATE INDEX file_hardlink_info_v3_DIR1 ON file_hardlink_info_v3(dir1)
CREATE INDEX file_hardlink_info_v3_MD5_HASH ON file_hardlink_info_v3(md5_hash)
CREATE INDEX file_hardlink_info_v3_MODIFY_TIME ON file_hardlink_info_v3(modify_time)
CREATE INDEX image_hardlink_info_v3_DIR1 ON image_hardlink_info_v3(dir1)
CREATE INDEX image_hardlink_info_v3_MD5_HASH ON image_hardlink_info_v3(md5_hash)
CREATE INDEX image_hardlink_info_v3_MODIFY_TIME ON image_hardlink_info_v3(modify_time)
CREATE INDEX talker_checkpoint_v3_MONTH_ID ON talker_checkpoint_v3(month_id)
CREATE INDEX video_hardlink_info_v3_DIR1 ON video_hardlink_info_v3(dir1)
CREATE INDEX video_hardlink_info_v3_MD5_HASH ON video_hardlink_info_v3(md5_hash)
CREATE INDEX video_hardlink_info_v3_MODIFY_TIME ON video_hardlink_info_v3(modify_time)
```

## head_image

用户头像相关

### head_image.db

```sql
CREATE TABLE head_image(username TEXT PRIMARY KEY, md5 TEXT, image_buffer BLOB, update_time INTEGER)
```

## ilinkvoip

### ilinkvoip.db

```sql
CREATE TABLE ilink_voip(wx_chatroom_ TEXT PRIMARY KEY, millsecond_ INTEGER, group_id_ TEXT, room_id_ INTEGER, room_key_ INTEGER, route_id_ INTEGER, voice_status_ INTEGER, talker_create_user_ TEXT, not_friend_user_list_ TEXT, members_ TEXT, is_ilink_ INTEGER)
```

## message

存储聊天记录相关。聊天消息内容存储在 `message_[0-9].db` 数据库的 `Msg_md5(username)` 表的 `message_content` 字段，`username` 在 `contact` 表根据 `nickname` 查询。

`local_type` 和 `message_content` 对照关系：

|`local_type`|消息类型|`message_content`格式|
|---|----|-----|
|1|文本消息|plain|
|3|图片消息|zstd_compress(xml)|
|34|语音消息|zstd_compress|
|42|名片消息|zstd_compress|
|43|视频消息|zstd_compress|
|47|动画表情|zstd_compress(xml)|
|48|位置消息|zstd_compress|
|244813135921|引用消息|zstd_compress(xml)|
|17179869233|卡片式链接（带描述）|zstd_compress(xml)|
|21474836529|卡片式链接/图文消息|zstd_compress(xml)|
|154618822705|小程序分享|zstd_compress(xml)|
|12884901937|音乐卡片|zstd_compress|
|8594229559345|红包卡片|zstd_compress|
|81604378673|聊天记录合并转发消息|zstd_compress|
|266287972401|拍一拍消息|zstd_compress|
|8589934592049|转账卡片|zstd_compress|
|270582939697|视频号直播卡片|zstd_compress|
|25769803825|文件消息|zstd_compress|
|10000|系统消息（撤回、加入群聊、群管理、群语音通话等）|plain or zstd_compress(xml)|

### biz_message_0.db

公众号消息记录

```sql
CREATE TABLE DeleteInfo(chat_name_id INTEGER, delete_table_name TEXT, CONSTRAINT UNIQUE_CHAT_DELETE UNIQUE(chat_name_id, delete_table_name))
CREATE TABLE DeleteResInfo(local_id INTEGER PRIMARY KEY AUTOINCREMENT, session_name_id INTEGER, msg_create_time INTEGER, msg_local_id INTEGER, res_path TEXT)
CREATE TABLE Msg_02628fb4b062917ee2a9d4d7bde609ad(local_id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, local_type INTEGER, sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, status INTEGER, upload_status INTEGER, download_status INTEGER, server_seq INTEGER, origin_source INTEGER, source TEXT, message_content TEXT, compress_content TEXT, packed_info_data BLOB, WCDB_CT_message_content INTEGER DEFAULT NULL, WCDB_CT_source INTEGER DEFAULT NULL)
CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY)
CREATE TABLE TimeStamp(timestamp INTEGER)
CREATE TABLE sqlite_sequence(name,seq)
CREATE TABLE wcdb_builtin_compression_record(tableName TEXT PRIMARY KEY, columns TEXT NOT NULL, rowid INTEGER) WITHOUT ROWID
CREATE INDEX DeleteInfo_CINDEX ON DeleteInfo(chat_name_id)
CREATE INDEX DeleteInfo_DINDEX ON DeleteInfo(delete_table_name)
CREATE INDEX DeleteResInfo_SCLINDEX ON DeleteResInfo(session_name_id, msg_create_time, msg_local_id)
CREATE INDEX Msg_02628fb4b062917ee2a9d4d7bde609ad_SENDERID ON Msg_02628fb4b062917ee2a9d4d7bde609ad(real_sender_id)
CREATE INDEX Msg_02628fb4b062917ee2a9d4d7bde609ad_SERVERID ON Msg_02628fb4b062917ee2a9d4d7bde609ad(server_id)
CREATE INDEX Msg_02628fb4b062917ee2a9d4d7bde609ad_SORTSEQ ON Msg_02628fb4b062917ee2a9d4d7bde609ad(sort_seq)
CREATE INDEX Msg_02628fb4b062917ee2a9d4d7bde609ad_TYPE_SEQ ON Msg_02628fb4b062917ee2a9d4d7bde609ad(local_type, sort_seq)
```

### media_0.db

语音消息内容

```sql
CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY)
CREATE TABLE TimeStamp(timestamp INTEGER)
CREATE TABLE VoiceInfo(chat_name_id INTEGER, create_time INTEGER, local_id INTEGER, svr_id INTEGER, voice_data BLOB, data_index TEXT DEFAULT '0')
CREATE INDEX VoiceInfo_INDEX ON VoiceInfo(chat_name_id, svr_id)
CREATE UNIQUE INDEX VoiceInfo_UNIQUE_INDEX ON VoiceInfo(chat_name_id, create_time, local_id, data_index)
```

### message_0.db

聊天记录

```sql
CREATE TABLE DeleteInfo(chat_name_id INTEGER, delete_table_name TEXT, CONSTRAINT UNIQUE_CHAT_DELETE UNIQUE(chat_name_id, delete_table_name))
CREATE TABLE DeleteResInfo(local_id INTEGER PRIMARY KEY AUTOINCREMENT, session_name_id INTEGER, msg_create_time INTEGER, msg_local_id INTEGER, res_path TEXT)
CREATE TABLE HistoryAddMsgInfo(session_name_id INTEGER, history_id INTEGER, server_id INTEGER, is_revoke INTEGER, CONSTRAINT _UNIQUEID PRIMARY KEY(session_name_id, history_id, server_id))
CREATE TABLE HistorySysMsgInfo(session_name_id INTEGER, history_id INTEGER, server_id INTEGER, is_revoke INTEGER, CONSTRAINT _UNIQUEID PRIMARY KEY(session_name_id, history_id, server_id))
CREATE TABLE Msg_02b1b63776348009fd33e5414b89b306(local_id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, local_type INTEGER, sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, status INTEGER, upload_status INTEGER, download_status INTEGER, server_seq INTEGER, origin_source INTEGER, source TEXT, message_content TEXT, compress_content TEXT, packed_info_data BLOB, WCDB_CT_message_content INTEGER DEFAULT NULL, WCDB_CT_source INTEGER DEFAULT NULL)
CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY)
CREATE TABLE SendInfo(chat_name_id INTEGER, msg_local_id INTEGER)
CREATE TABLE TimeStamp(timestamp INTEGER)
CREATE TABLE sqlite_sequence(name,seq)
CREATE TABLE wcdb_builtin_compression_record(tableName TEXT PRIMARY KEY, columns TEXT NOT NULL, rowid INTEGER) WITHOUT ROWID
CREATE INDEX DeleteInfo_CINDEX ON DeleteInfo(chat_name_id)
CREATE INDEX DeleteInfo_DINDEX ON DeleteInfo(delete_table_name)
CREATE INDEX DeleteResInfo_SCLINDEX ON DeleteResInfo(session_name_id, msg_create_time, msg_local_id)
CREATE INDEX Msg_02b1b63776348009fd33e5414b89b306_SENDERID ON Msg_02b1b63776348009fd33e5414b89b306(real_sender_id)
CREATE INDEX Msg_02b1b63776348009fd33e5414b89b306_SERVERID ON Msg_02b1b63776348009fd33e5414b89b306(server_id)
CREATE INDEX Msg_02b1b63776348009fd33e5414b89b306_SORTSEQ ON Msg_02b1b63776348009fd33e5414b89b306(sort_seq)
CREATE INDEX Msg_02b1b63776348009fd33e5414b89b306_TYPE_SEQ ON Msg_02b1b63776348009fd33e5414b89b306(local_type, sort_seq)
CREATE UNIQUE INDEX SendInfo_CHATNAME_LOCALID ON SendInfo(chat_name_id, msg_local_id)
```

### message_fts.db

```sql
CREATE VIRTUAL TABLE message_fts_v3_0 USING fts5(tokenize = 'MMFtsTokenizer disable_pinyin', acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED, session_id UNINDEXED, sender_id UNINDEXED)
CREATE TABLE 'message_fts_v3_0_config'(k PRIMARY KEY, v) WITHOUT ROWID
CREATE TABLE 'message_fts_v3_0_content'(id INTEGER PRIMARY KEY, c0, c1, c2, c3, c4, c5)
CREATE TABLE 'message_fts_v3_0_data'(id INTEGER PRIMARY KEY, block BLOB)
CREATE TABLE 'message_fts_v3_0_docsize'(id INTEGER PRIMARY KEY, sz BLOB)
CREATE TABLE 'message_fts_v3_0_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID
CREATE TABLE message_fts_v3_aux_0(message_local_id INTEGER, sort_seq INTEGER, session_id INTEGER, CONSTRAINT sessionId_localId_sortseq PRIMARY KEY(session_id, message_local_id, sort_seq))
CREATE TABLE message_fts_v3_range(db_time_stamp INTEGER, start_local_id INTEGER, end_local_id INTEGER, session_id INTEGER, CONSTRAINT sessionId_dbTime PRIMARY KEY(session_id, db_time_stamp))
CREATE TABLE message_fts_v3_session_delete_info(session_id INTEGER, start_local_id INTEGER, end_local_id INTEGER, db_time_stamp INTEGER, CONSTRAINT sessionId_dbtime PRIMARY KEY(session_id, db_time_stamp))
CREATE TABLE name2id(username TEXT PRIMARY KEY)
CREATE TABLE table_info(Key TEXT PRIMARY KEY, ValueInt64 INTEGER, ValueDouble REAL, ValueStdStr TEXT, ValueBlob BLOB)
```

### message_revoke.db

该数据库只存储本人撤回的消息，不存其他人撤回的消息

```sql
CREATE TABLE revokemessage(to_user_name TEXT, svr_id INTEGER, message_type INTEGER, revoke_time INTEGER, content TEXT, at_user_list TEXT)
CREATE INDEX revokemessage_revoke_time ON revokemessage(revoke_time)
CREATE UNIQUE INDEX revokemessage_svr_id_to_user_name ON revokemessage(svr_id, to_user_name)
```

## newtips

### newtips.db

```sql
CREATE TABLE new_tips(unique_id TEXT PRIMARY KEY, disable INTEGER, new_tips_content TEXT)
```

## session

窗口会话

### session.db

```sql
CREATE TABLE SessionDeleteTable(username TEXT PRIMARY KEY, delete_time INTEGER)
CREATE TABLE SessionTable(username TEXT PRIMARY KEY, type INTEGER, unread_count INTEGER, unread_first_msg_srv_id INTEGER, is_hidden INTEGER, summary TEXT, draft TEXT, status INTEGER, last_timestamp INTEGER, sort_timestamp INTEGER, last_clear_unread_timestamp INTEGER, last_msg_locald_id INTEGER, last_msg_type INTEGER, last_msg_sub_type INTEGER, last_msg_sender TEXT, last_sender_display_name TEXT)
CREATE INDEX SessionTable_LSENDER ON SessionTable(last_msg_sender)
CREATE INDEX SessionTable_TYPE ON SessionTable(type)
```

## sns

朋友圈相关

### sns.db

```sql
CREATE TABLE SnsErrorMessage(local_id INTEGER PRIMARY KEY AUTOINCREMENT, error_type INTEGER, creat_time INTEGER, tid INTEGER, packed_info_data TEXT)
CREATE TABLE SnsIgnoredDataItem(tid INTEGER PRIMARY KEY)
CREATE TABLE SnsMainTimeLineBreakFlag(tid INTEGER, tid_heigh_bit INTEGER, tid_low_bit INTEGER, break_flag INTEGER, CONSTRAINT _heigh_low_bit_tid PRIMARY KEY(tid_heigh_bit DESC, tid_low_bit DESC))
CREATE TABLE SnsMessage_tmp3(local_id INTEGER PRIMARY KEY AUTOINCREMENT, create_time INTEGER, type INTEGER, feed_id INTEGER, is_unread INTEGER, from_username TEXT, from_nickname TEXT, to_username TEXT, to_nickname TEXT, content TEXT, serialized_comment TEXT, serialized_ref TEXT, comment_id INTEGER, client_id TEXT, comment64_id INTEGER, comment_flag INTEGER)
CREATE TABLE SnsNoteVoice(tid INTEGER, data_id TEXT, buff TEXT, CONSTRAINT _tid_data_id PRIMARY KEY(tid, data_id))
CREATE TABLE SnsTimeLine(tid INTEGER PRIMARY KEY DESC, user_name TEXT, content TEXT)
CREATE TABLE SnsUserTimeLineBreakFlag(tid INTEGER, tid_heigh_bit INTEGER, tid_low_bit INTEGER, break_flag INTEGER, user_name TEXT, CONSTRAINT _heigh_low_bit_tid PRIMARY KEY(tid_heigh_bit DESC, tid_low_bit DESC))
CREATE TABLE sqlite_sequence(name,seq)
CREATE INDEX SnsErrorMessage_tid ON SnsErrorMessage(tid)
CREATE INDEX SnsMessage_tmp3_create_time_local_id ON SnsMessage_tmp3(create_time DESC, local_id DESC)
CREATE INDEX SnsUserTimeLineBreakFlag_user_name ON SnsUserTimeLineBreakFlag(user_name)
```

## wcfinder

### wcfinder.db

```sql
CREATE TABLE wcfinderlivestatus(finder_live_id INTEGER, finder_username TEXT, finder_export_id TEXT, live_status INTEGER, replay_status INTEGER, charge_flag INTEGER)
CREATE TABLE wcfinderuserpage(username TEXT, extra_buffer BLOB)
CREATE UNIQUE INDEX wcfinderlivestatus_finder_live_id_username ON wcfinderlivestatus(finder_live_id, finder_username, finder_export_id)
CREATE UNIQUE INDEX wcfinderuserpage_finder_user_page_username ON wcfinderuserpage(username)
```
