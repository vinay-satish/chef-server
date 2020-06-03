%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Eric B Merritt <ericbmerritt@gmail.com>
%% Copyright 2012 Opscode, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%

-module(bksw_sec).

-include_lib("eunit/include/eunit.hrl").

-export([is_authorized/2]).
-compile(export_all).

-define(SECONDS_AT_EPOCH, 62167219200).
-include("internal.hrl").

%%===================================================================
%% API functions
%%===================================================================
%-ifdef(TEST).
%is_authorized(Req, Context) ->
%    {true, Req, Context}.
%-else.
is_authorized(Req0, #context{auth_check_disabled=true} = Context) ->
    {true, Req0, Context};
is_authorized(Req0, #context{} = Context) ->
    Headers = mochiweb_headers:to_list(wrq:req_headers(Req0)),
    {RequestId, Req1} = bksw_req:with_amz_request_id(Req0),
    case proplists:get_value('Authorization', Headers, undefined) of
        undefined ->
            do_signed_url_authorization(RequestId, Req1, Context, Headers);
        IncomingAuth ->
            io:format("~ndoing standard authorization", []),
            do_standard_authorization(RequestId, IncomingAuth, Req1, Context, Headers)
    end.
%-endif.

% presigned url verification
% https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
do_signed_url_authorization(RequestId, Req0, Context, Headers0) ->

%    %io:format("~n~n--------------------------------", []),
    io:format("~nin bksw_sec do_signed_url_authorization", []),

    QueryParams = wrq:req_qs(Req0),
    io:format("~nquery string: ~p", [QueryParams]),

    Credential = wrq:get_qs_value("X-Amz-Credential", "", Req0),
    io:format("~nx-amz-credential:  ~p", [wrq:get_qs_value("X-Amz-Credential", "", Req0)]),

    % can be undefined
    XAmzDate = wrq:get_qs_value("X-Amz-Date", "", Req0),
    io:format("~nXAmzDate: ~p", [XAmzDate]),

    SignedHeaderKeysString = wrq:get_qs_value("X-Amz-SignedHeaders", "", Req0),
    io:format("~nsigned header keys string: ~p", [SignedHeaderKeysString]),

    IncomingSignature = wrq:get_qs_value("X-Amz-Signature", "", Req0),
    io:format("~nincoming signature: ~p", [IncomingSignature]),

    % only used with query string (presigned url)
    % authentication, not with authorization header
    % 1 =< XAmzExpires =< 604800
    XAmzExpiresString = wrq:get_qs_value("X-Amz-Expires", "", Req0),
    io:format("~nx-amz-expires: ~p", [XAmzExpiresString]),

    io:format("~ncalling do_common_authorization", []),
    do_common_authorization(RequestId, Req0, Context, Credential, XAmzDate, SignedHeaderKeysString, IncomingSignature, XAmzExpiresString, Headers0, presigned_url).

% https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
do_standard_authorization(RequestId, IncomingAuth, Req0, Context, Headers0) ->
    try
    io:format("~nDOING STANDARD AUTHORIZATION", []),
    io:format("~nIncomingAuth: ~p", [IncomingAuth]),

    (ParseAuth = parse_authorization(IncomingAuth)) /= err orelse throw({RequestId, Req0, Context}),
    [Credential, SignedHeaderKeysString, IncomingSignature] = ParseAuth,
    io:format("~nAuthorization:~n~p~n~p~n~p", [Credential, SignedHeaderKeysString, IncomingSignature]),
%    [AWSAccessKeyId, CredentialScopeDate | _]  = parse_x_amz_credential(Credential),
%    %io:format("~naws-access-key-id: ~p~nCredentialScopeDate: ~p", [AWSAccessKeyId, CredentialScopeDate]),

    % can be undefined
    XAmzDate = wrq:get_req_header("x-amz-date", Req0),
    io:format("~nXAmzDate: ~p", [XAmzDate]),

    io:format("~ncalling do_common_authorization", []),
    do_common_authorization(RequestId, Req0, Context, Credential, XAmzDate, SignedHeaderKeysString, IncomingSignature, "300", Headers0, authorization_header)

    catch
        {RequestId, Req0, Context} -> encode_access_denied_error_response(RequestId, Req0, Context)
    end.

%%-ifdef(TESTxxx).
%%% tests sometimes use the following credentials:
%%% AccessKey = "e1efc99729beb175"
%%% SecretKey = "fc683cd9ed1990ca"
%%getkeys("e1efc99729beb175", _) ->
%%    {"e1efc99729beb175", "fc683cd9ed1990ca"};
%%getkeys(<<"e1efc99729beb175">>, _) ->
%%    {<<"e1efc99729beb175">>, <<"fc683cd9ed1990ca">>};
%%getkeys("ASIAXXFRTNDYFRUTH6NY", _) ->
%%    {"ASIAXXFRTNDYFRUTH6NY", "ogxnfFC1rjltSjQI6boQ5tBg4mMG5wydPilkgQzU"};
getkeys(_, Context) ->
    {bksw_conf:access_key_id(Context), bksw_conf:secret_access_key(Context)}.
%%    %bksw_conf:keys().
%%-else.
%getkeys(_, Context) ->
%    {bksw_conf:access_key_id(Context), bksw_conf:secret_access_key(Context)}.
%%-endif.

do_common_authorization(RequestId, Req0, #context{reqid = ReqId} = Context, Credential, XAmzDate, SignedHeaderKeysString, IncomingSignature, XAmzExpiresString, Headers0, VerificationType) ->
    try

    % handle undefined, err

    (Host = wrq:get_req_header("Host", Req0)) /= undefined orelse throw({RequestId, Req0, Context}),

    (ParseCred = parse_x_amz_credential(Credential)) /= err orelse throw({RequestId, Req0, Context}),
    [AWSAccessKeyId, CredentialScopeDate, Region | _] = ParseCred,

    % TODO: explain rationale for doing it this way (ease of unit testing)
    % https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
    DateIfUndefined = fun() -> wrq:get_req_header("date", Req0) end,
    (Date = get_check_date(XAmzDate, DateIfUndefined, CredentialScopeDate)) /= err orelse throw({RequestId, Req0, Context}),



    {AccessKey, SecretKey} = getkeys(AWSAccessKeyId, Context),
    %{AccessKey, SecretKey} = {"e1efc99729beb175", "fc683cd9ed1990ca"},

    io:format("~naws-access-key-id: ~p", [AWSAccessKeyId]),
    io:format("~naccess-key-id: ~p",     [AccessKey]),
    io:format("~nsecret-access-key: ~p", [SecretKey]),

    Headers = process_headers(Headers0),

    SignedHeaderKeys = parse_x_amz_signed_headers(SignedHeaderKeysString),
    SignedHeaders = get_signed_headers(SignedHeaderKeys, Headers, []),

    RawMethod = wrq:method(Req0),
    Method = list_to_atom(string:to_lower(erlang:atom_to_list(RawMethod))),
    io:format("~nmethod: ~p", [Method]),

io:format("~nscheme: ~p", [wrq:scheme(Req0)]),
io:format("~napp_root: ~p", [wrq:app_root(Req0)]),
io:format("~nbase_uri: ~p", [wrq:base_uri(Req0)]),

    Path  = wrq:path(Req0),
    io:format("~npath: ~p", [Path]),
    DispPath  = wrq:disp_path(Req0),
    io:format("~ndisp_path: ~p", [DispPath]),
    RawPath  = wrq:raw_path(Req0),
    io:format("~nrawpath: ~p", [RawPath]),
    PathTokens  = wrq:path_tokens(Req0),
    io:format("~npath-tokens: ~p", [PathTokens]),

    {BucketName, Key} = get_bucket_key(Path),
    io:format("~nbucketname: ~p", [BucketName]),
    io:format("~nkey: ~p", [Key]),

%TODO:
% would be nice when flagging errors to flag more specific errors than signing error or forbidden,
% and write pedant tests to check those errors.

    % which key/secret to use?
    % what to use for host value?
    % make sure to set the region and service here? or check defaults
    % TODO: new may eventually need to support ipv6, entailing passing in options.
    Config = mini_s3:new(AccessKey, SecretKey, Host),
    AltHost = mini_s3:get_host_toggleport(Host, Config), 
    AltSignedHeaders = [case {K, V} of {"host", _} -> {"host", AltHost}; _ -> {K, V} end || {K, V} <- SignedHeaders],

io:format("~nhost_tokens: ~p", [wrq:host_tokens(Req0)]),
    io:format("~nhost: ~p", [Host]),
    io:format("~nAltHost: ~p", [AltHost]),
    io:format("~nheaders: ~p", [Headers]),
    io:format("~nsigned headers: ~p", [SignedHeaders]),
    io:format("~nAltSignedHeaders: ~p", [AltSignedHeaders]),

    Url = erlcloud_s3:get_object_url(BucketName, Key, Config),
    io:format("~nerlcloud_s3:get_object_url: ~p", [Url]),
    io:format("~nTODO: this path needs to be escaped ^^^", []),

%    This (below) caused a big webmachine error
%    if you reference as full body vs chunked, you can't reference it the other way and vice versa
%    Payload = wrq:req_body(Req0),
%    %io:format("~nbody (payload?): ~p", [Payload]),

    XAmzExpires = list_to_integer(XAmzExpiresString),

    case VerificationType of
        presigned_url ->
            io:format("~nverification type: presigned_url", []),

            "AWS4-HMAC-SHA256" == wrq:get_qs_value("X-Amz-Algorithm", Req0) orelse throw({RequestId, Req0, Context}),

            % temporarily disabling this - should be re-enabled later
            %true == check_signed_headers_common(SignedHeaders, Headers) orelse throw({RequestId, Req0, Context}),
            check_signed_headers_common(SignedHeaders, Headers),

            ComparisonURL = mini_s3:s3_url(Method, BucketName, Key, XAmzExpires, SignedHeaders, Date, Config),
            io:format("~ncomparison url: ~p", [ComparisonURL]),

            % list_to_binary profiled faster than binary_to_list,
            % so use that for conversion and comparison.
            IncomingSig = list_to_binary(IncomingSignature),

            % compare signatures.  assumes X-Amz-Signature is always on the end?
            [_, ComparisonSig] = string:split(ComparisonURL, "&X-Amz-Signature=", all),
            io:format("~ncomparison sig: ~p", [ComparisonSig]),

            Sig1 = case IncomingSig of
                ComparisonSig ->
                    io:format("~nSig1 = case IncomingSig (~p) of ComparisonSig (~p) -> Sig1 = IncomingSig", [IncomingSig, ComparisonSig]),
                    AltComparisonSig = "not computed",
                    IncomingSig;
                _ ->
                    AltComparisonURL = mini_s3:s3_url(Method, BucketName, Key, XAmzExpires, AltSignedHeaders, Date, Config),
                    io:format("~nalt comparison url: ~p", [AltComparisonURL]),
                    [_, AltComparisonSig] = string:split(AltComparisonURL, "&X-Amz-Signature=", all),
                    io:format("~nalt comparison sig: ~p", [AltComparisonSig]),
                    io:format("~nSig1 = case IncomingSig (~p) of AltComparisonSig (~p) -> Sig1 = AltComparisonSig", [IncomingSig, AltComparisonSig]),
                    AltComparisonSig
                end;


        authorization_header ->
            io:format("~nverification type: authorization_header", []),

            ComparisonURL = "blah",
            QueryParams = wrq:req_qs(Req0),
            io:format("~nQueryParams: ~p", [QueryParams]),

            % temporarily disabling this - should be re-enabled later
            %true == check_signed_headers_authhead(SignedHeaders, Headers) orelse throw({RequestId, Req0, Context}),
            check_signed_headers_authhead(SignedHeaders, Headers),

            % this header will be calculated and should not be passed-in
%            SignedHeadersNo256 = lists:keydelete("x-amz-content-sha256", 1, SignedHeaders),

            %SigV4Headers = erlcloud_aws:sign_v4(list_to_atom(Method), Url, Config, Headers, Payload, Region, "s3", QueryParams, Date),
            %SigV4Headers = erlcloud_aws:sign_v4(list_to_atom(Method), Url, Config, SignedHeaders, "UNSIGNED-PAYLOAD", Region, "s3", QueryParams, Date),
            % removed payload (replaced with <<>>), signedheaders = host: api, changed Url for Path
            %SigV4Headers = erlcloud_aws:sign_v4(list_to_atom(Method), Path, Config, [{"host", "api"}], <<>>, Region, "s3", QueryParams, Date),
            % unsigned payload
%            SigV4Headers = erlcloud_aws:sign_v4(list_to_atom(Method), Path, Config, SignedHeadersNo256, <<>>, Region, "s3", QueryParams, Date),
            SigV4Headers = erlcloud_aws:sign_v4(Method, Path, Config, SignedHeaders, <<>>, Region, "s3", QueryParams, Date),
            io:format("~nsigv4headers: ~p", [SigV4Headers]),

            IncomingSig = IncomingSignature,

            (ParseAuth = parse_authorization(proplists:get_value("Authorization", SigV4Headers, ""))) /= err orelse throw({RequestId, Req0, Context}),
            [_, _, ComparisonSig] = ParseAuth,
            io:format("~ncomparison sig: ~p", [ComparisonSig]),

            Sig1 = case IncomingSig of
                ComparisonSig ->
                    AltComparisonSig = "not computed",
                    IncomingSig;
                _ ->
                    AltSigV4Headers = erlcloud_aws:sign_v4(Method, Path, Config, AltSignedHeaders, <<>>, Region, "s3", QueryParams, Date),
                    (AltParseAuth = parse_authorization(proplists:get_value("Authorization", AltSigV4Headers, ""))) /= err orelse throw({RequestId, Req0, Context}),
                    [_, _, AltComparisonSig] = AltParseAuth,
                    io:format("~nalt comparison sig: ~p", [AltComparisonSig]),
                    AltComparisonSig
                end
    end,

    io:format("~nIncomingSig: ~p",      [IncomingSig        ]),
    io:format("~nSig1: ~p",             [Sig1               ]),
    io:format("~nComparisonSig: ~p",    [ComparisonSig      ]),
    io:format("~nAltComparisonSig: ~p", [AltComparisonSig   ]),

    case IncomingSig of
        Sig1 ->
            io:format("~ncase IncomingSig (~p) of Sig1 (~p)...", [Sig1, ComparisonSig]),
            case is_expired(Date, XAmzExpires) of
                true ->
                    io:format("~nexpired signature", []),
                    ?LOG_DEBUG("req_id=~p expired signature (~p) for ~p",
                               [ReqId, XAmzExpires, Path]),
                    encode_access_denied_error_response(RequestId, Req0, Context);
                false ->
                    case erlang:iolist_to_binary(AWSAccessKeyId) ==
                               erlang:iolist_to_binary(AccessKey) of
                        true ->
                            MaxAge = "max-age=" ++ XAmzExpiresString,
                            Req1 = wrq:set_resp_header("Cache-Control", MaxAge, Req0),
                            io:format("~ndo_signed_url_authorization succeeded", []),
                            io:format("~n-------------------------------------", []),
                            {true, Req1, Context};
                        false ->
                            io:format("~ndo_signed_url_authorization failed", []),
                            io:format("~n----------------------------------", []),
                            ?LOG_DEBUG("req_id=~p signing error for ~p", [ReqId, Path]),
                            encode_sign_error_response(AWSAccessKeyId, IncomingSignature, RequestId,
                                                       ComparisonURL, Req0, Context)
                    end
            end;
        _X ->
            io:format("~ncase Sig1 (~p) of _X (~p)...", [Sig1, _X]),
            io:format("~nbksw_sec: do_signed_url_authorization failed", []),
            io:format("~n--------------------------------------------", []),
            encode_access_denied_error_response(RequestId, Req0, Context)
    end

    catch
        {RequestId, Req0, Context} -> encode_access_denied_error_response(RequestId, Req0, Context)
    end.


%    %Headers = mochiweb_headers:to_list(wrq:req_headers(Req0)),
%    %AmzHeaders = amz_headers(Headers),
%    RawMethod = wrq:method(Req0),
%    Method = string:to_lower(erlang:atom_to_list(RawMethod)),
%    ContentMD5 = proplists:get_value('Content-Md5', Headers, ""),
%    ContentType = proplists:get_value('Content-Type', Headers, ""),
%    Date = proplists:get_value('Date', Headers, ""),
%    %% get_object_and_bucket decodes the bucket, but the request will have been signed with
%    %% the encoded bucket.
%    {ok, Bucket0, Resource} = bksw_util:get_object_and_bucket(Req0),
%    Bucket = bksw_io_names:encode(Bucket0),
%    AccessKey = bksw_conf:access_key_id(Context),
%    SecretKey = bksw_conf:secret_access_key(Context),
%
%    {StringToSign, RawCheckedAuth} =
%        mini_s3:make_authorization(AccessKey, SecretKey,
%                                   erlang:list_to_existing_atom(Method),
%                                   bksw_util:to_string(ContentMD5),
%                                   bksw_util:to_string(ContentType),
%                                   bksw_util:to_string(Date),
%                                   %AmzHeaders,
%                                   "blah",
%                                   bksw_util:to_string(Bucket),
%                                   "/" ++ bksw_util:to_string(Resource),
%                                   ""),
%    CheckedAuth = erlang:iolist_to_binary(RawCheckedAuth),
%    [AccessKeyId, Signature] = ["x", "x"], %split_authorization(IncomingAuth),
%    case erlang:iolist_to_binary(IncomingAuth) of
%        CheckedAuth ->
%            {true, Req0, Context};
%        _ ->
%            encode_sign_error_response(AccessKeyId, Signature,
%                                       RequestId, StringToSign, Req0, Context)
%    end.

%case make_signed_url_authorization(SecretKey,
%                                       Method,
%                                       Path,
%                                       Expires,
%                                       Headers) of
%        {StringToSign, Signature} ->
%            case ExpireDiff =< 0 of
%                true ->
%                    ?LOG_DEBUG("req_id=~p expired signature (~p) for ~p",
%                               [ReqId, Expires, Path]),
%                    encode_access_denied_error_response(RequestId, Req0, Context);
%                false ->
%% temp hack
%%                    case ((erlang:iolist_to_binary(AWSAccessKeyId) ==
%%                               erlang:iolist_to_binary(AccessKey)) andalso
%%                          erlang:iolist_to_binary(Signature) ==
%%                              erlang:iolist_to_binary(IncomingSignature)) of
%case true of
%                        true ->
%                            MaxAge = "max-age=" ++ integer_to_list(ExpireDiff),
%                            Req1 = wrq:set_resp_header("Cache-Control", MaxAge, Req0),
%%io:format("~ndo_signed_url_authorization succeeded", []),
%%io:format("~n--------------------------------", []),
%                            {true, Req1, Context};
%                        false ->
%%io:format("~ndo_signed_url_authorization failed", []),
%%io:format("~n--------------------------------", []),
%                            ?LOG_DEBUG("req_id=~p signing error for ~p", [ReqId, Path]),
%                            encode_sign_error_response(AWSAccessKeyId, IncomingSignature, RequestId,
%                                                       StringToSign, Req0, Context)
%                    end
%                end;
%        error ->
%%io:format("~nbksw_sec: make_signed_url_authorization failed", []),
%%io:format("~n--------------------------------", []),
%            encode_access_denied_error_response(RequestId, Req0, Context)
%    end.

% https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
%-spec check_signed_headers_authhead(proplist(), proplist()) -> boolean(). % for erlang20+
-spec check_signed_headers_authhead([tuple()], [tuple()]) -> boolean().
check_signed_headers_authhead(SignedHeaders, Headers) ->
%    check_signed_headers_common(SignedHeaders, Headers) andalso
%
%    % x-amz-content-sha256 header is required
%    proplists:is_defined("x-amz-content-sha256", SignedHeaders) andalso
%
%    % if content-type header is present in request, it is required
%    case proplists:is_defined("content-type", Headers) of
%        true ->
%            proplists:is_defined("content-type", SignedHeaders);
%        _ ->
%            true
%    end.
io:format("~nchecking headers...", []),
check_signed_headers_common(SignedHeaders, Headers),

% x-amz-content-sha256 header is required
io:format("~nx-amz-content-sha256 present: ~p", [proplists:is_defined("x-amz-content-sha256", SignedHeaders)]),

% if content-type header is present in request, it is required
case proplists:is_defined("content-type", Headers) of
    true ->
        io:format("~ncontent-type header present in request AND signed: ~p", [proplists:is_defined("content-type", SignedHeaders)]);
    _ ->
        true
end.

% required signed headers common to both authorization header verification
% and presigned url verification.
% https://docs.amazonaws.cn/en_us/AmazonS3/latest/API/sigv4-query-string-auth.html
%-spec check_signed_headers_common(proplist(), proplist()) -> boolean(). % for erlang20+
-spec check_signed_headers_common([tuple()], [tuple()]) -> boolean().
check_signed_headers_common(SignedHeaders, Headers) ->
%    % host header is required
%    proplists:is_defined("host", SignedHeaders) andalso
%
%    % any x-amz-* headers present in request are required
%    [] == [Key || {Key, _} <- Headers, is_amz(Key), not proplists:is_defined(Key, SignedHeaders)].
io:format("~nchecking headers...", []),
io:format("~nhost header present: ~p", [proplists:is_defined("host", SignedHeaders)]),
io:format("~nx-amz-* headers in request but not signed (should be none): ~p", [[Key || {Key, _} <- Headers, is_amz(Key), not proplists:is_defined(Key, SignedHeaders)]]),

% any x-amz-* headers present in request are required
[] == [Key || {Key, _} <- Headers, is_amz(Key), not proplists:is_defined(Key, SignedHeaders)].

% split  "<bucketname>/<key>" (possibly leading-trailing /) into {"bucketname", "key"}
% Path = "<bucketname>/<key>"
-spec get_bucket_key(string()) -> {string(), string()}.
get_bucket_key(Path) ->
    %case string:tokens(  Path) of
    case string:lexemes(Path, "/") of % for erlang 22+
        [            ] -> {"",     ""};
        [Bucket      ] -> {Bucket, ""};
        [Bucket | Key] -> {Bucket, filename:join(Key)}
    end.

% TODO: change A,B,C etc to Y1, Y2, M1, M2, etc...
% https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
-spec get_check_date(string(), string(), string()) -> string() | err.
get_check_date(ISO8601Date, DateIfUndefined, [A, B, C, D, E, F, G, H]) ->
    Date = case ISO8601Date of
               undefined -> DateIfUndefined();
               _         -> ISO8601Date
           end,
    case Date of
        [A, B, C, D, E, F, G, H, $T, _, _, _, _, _, _, $Z] -> Date;
        _                                                  -> err
    end.

%% get key-value pairs (headers) associated with specified keys
%get_signed_headers(SignedHeaderKeys, Headers) ->
%    lists:flatten([proplists:lookup_all(SignedHeaderKey, Headers) || SignedHeaderKey <- SignedHeaderKeys]).

%TODO: change spec to parameter::type (or whatever it is - look it up)
%TODO: possibly simplify logic since efficiency should not be a concern.
%TODO: look at 434, test to see if that 2nd empty list can actually happen.
%TODO: look at the unit test, consider integration test (pedant test).
% get key-value pairs (headers) associated with specified keys.
% for each key, get first occurance of key-value. for duplicated
% keys, get corresponding key-value pairs. results are undefined
% for nonexistent key(s).
%-spec get_signed_headers(proplist(), proplist(), proplist()) -> proplist(). % for erlang20+
-spec get_signed_headers([tuple()], [tuple()], [tuple()]) -> [tuple()].
get_signed_headers([], _, SignedHeaders) -> lists:reverse(SignedHeaders);
get_signed_headers(_, [], SignedHeaders) -> lists:reverse(SignedHeaders);
get_signed_headers([Key | SignedHeaderKeys], Headers0, SignedHeaders) ->
    {_, SignedHeader, Headers} = lists:keytake(Key, 1, Headers0),
    get_signed_headers(SignedHeaderKeys, Headers, [SignedHeader | SignedHeaders]).

% split authorization header into component parts
% https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
- spec parse_authorization(string()) -> [string()] | err.
parse_authorization(Auth) ->
    case string:split(Auth, " ", all) of
        ["AWS4-HMAC-SHA256", "Credential="++Cred, "SignedHeaders="++SigHead, "Signature="++Signature] ->
            [string:trim(Cred, trailing, ","), string:trim(SigHead, trailing, ","), Signature];
        _ ->
            err
    end.

% split credentials string into component parts
% Cred = "<access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request"
- spec parse_x_amz_credential(string()) -> [string()].
parse_x_amz_credential(Cred) ->
    X = string:split(Cred, "/", all),
    case X of
        [_access_key_id, _date, _aws_region, "s3", "aws4_request"] -> X;
        _                                                          -> err
    end.

%TODO: explain rationale
% split signed header string into component parts
% Headers = "<header1>;<header2>;...<headerN>"
- spec parse_x_amz_signed_headers(string()) -> [string()].
parse_x_amz_signed_headers(Headers) ->
   string:split(Headers, ";", all).

% convert the keys of key-value pairs to lowercase strings
%-spec process_headers([proplist()]) -> [proplist()]. % for erlang20+
-spec process_headers([tuple()]) -> [tuple()].
process_headers(Headers) ->
    [{string:casefold(
        case is_atom(Key) of
            true -> atom_to_list(Key);
            _    -> Key
        end), Val} || {Key, Val} <- Headers].

%make_signed_url_authorization(SecretKey, Method, Path, Expires, Headers) ->
%    try
%        mini_s3:make_signed_url_authorization(SecretKey,
%                                              erlang:list_to_existing_atom(Method),
%                                              Path,
%                                              Expires,
%                                              Headers)
%    catch
%        _:Why ->
%            error_logger:error_report({error, {{mini_s3, make_signed_url_authorization},
%                                               [<<"SECRETKEY">>, Method, Path, Expires, Headers],
%                                               Why}}),
%            error
%    end.

%-spec expire_diff(undefined | binary()) -> integer().
%expire_diff(undefined) -> 1;
%expire_diff(Expires) ->
%    Now = calendar:datetime_to_gregorian_seconds(erlang:universaltime()),
%    bksw_util:to_integer(Expires) - (Now - ?SECONDS_AT_EPOCH).

%TODO: praj says os:timestamp() may not be recommended.  look into alternative.
% maybe erlang:monotonic_time?
% make sure everything is timewarp safe.
% https://erlang.org/doc/apps/erts/time_correction.html
-spec is_expired(string(), integer()) -> boolean().
is_expired(DateTimeString, ExpiresInSecondsInt) ->
    % most ways of getting the date/time seem problematic.  for instance, docs for
    % calendar:universal_time() and erlang:universaltime() say: 'Returns local time
    % if universal time is unavailable.'
    % since it is unknown which time would be used, we could use local time and
    % convert to universal.  however, local time could be an 'illegal' time wrt
    % universal time if switching to/from daylight savings time.

    UniversalTimeInSec = calendar:datetime_to_gregorian_seconds(calendar:now_to_universal_time(os:timestamp())),

    [Y1, Y2, Y3, Y4, M1, M2, D1, D2, _, H1, H2, N1, N2, S1, S2, _] = DateTimeString,
    Year    = list_to_integer([Y1, Y2, Y3, Y4]),
    Month   = list_to_integer([M1, M2        ]),
    Day     = list_to_integer([D1, D2        ]),
    Hour    = list_to_integer([H1, H2        ]),
    Min     = list_to_integer([N1, N2        ]),
    Sec     = list_to_integer([S1, S2        ]),

    % this could be used to check if the date constructed is valid
    % calendar:valid_date({{Year, Month, Day}, {Hour, Min, Sec}}),

    DateSeconds = calendar:datetime_to_gregorian_seconds({{Year, Month, Day}, {Hour, Min, Sec}}),
    DateSeconds + ExpiresInSecondsInt < UniversalTimeInSec.

%% get_bucket([Bucket, _, _]) ->
%%     Bucket.

encode_sign_error_response(AccessKeyId, Signature,
                           RequestId, StringToSign, Req0,
                          Context) ->
    Req1 = bksw_req:with_amz_id_2(Req0),
    Body = bksw_xml:signature_does_not_match_error(
             RequestId, bksw_util:to_string(Signature),
             bksw_util:to_string(StringToSign),
             bksw_util:to_string(AccessKeyId)),
    Req2 = wrq:set_resp_body(Body, Req1),
    {{halt, 403}, Req2, Context}.

encode_access_denied_error_response(RequestId, Req0, Context) ->
    Req1 = bksw_req:with_amz_id_2(Req0),
    Body = bksw_xml:access_denied_error(RequestId),
    Req2 = wrq:set_resp_body(Body, Req1),
    {{halt, 403}, Req2, Context}.

-spec is_amz(string()) -> boolean().
is_amz([$x, $-, $a, $m, $z, $- | _]) ->
    true;
is_amz([$X, $-, $A, $m, $z, $- | _]) ->
    true;
is_amz(_) ->
    false.

%split_authorization([$A, $W, $S, $\s, $: | Rest]) ->
%    [<<>>, Rest];
%split_authorization([$A, $W, $S, $\s  | Rest]) ->
%    string:tokens(Rest, ":").

%amz_headers(Headers) ->
%    [{process_header(K), V} || {K,V} <- Headers, is_amz(K)].

%process_header(Key) ->
%    string:to_lower(bksw_util:to_string(Key)).
