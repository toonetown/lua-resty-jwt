use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua '
      local cjson = require "cjson.safe"
      function __runSay(fn, ...)
        local status, rslt = pcall(fn, ...)
        if status then
          local t = type(rslt)
          if t == "function" or t == "nil" then
            ngx.say("TYPE: " .. t)
          elseif t == "table" then
            local cjson = require "cjson.safe"
            ngx.say(cjson.encode(rslt))
          else
            ngx.say(rslt)
          end
        else
          ngx.say(rslt.reason or string.gsub(rslt, "^.*: ", ""))
        end
      end
      function __testValidator(validator, spec, obj)
        if spec == "__jwt" then
          __runSay(validator, obj, spec, cjson.encode(obj))
        else
          __runSay(validator, obj.payload[spec], spec, cjson.encode(obj))
        end
      end
    ';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 72: Validator.opt_is_at
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_is_at()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a positive numeric value.
true
'past' claim is only valid at Fri, 21 Apr 2000 22:09:58 GMT
'future' claim is only valid at Wed, 21 Apr 2100 22:09:58 GMT
--- no_error_log
[error]


=== TEST 73: Validator.opt_is_at with leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(3153600000)
            local tval = validators.opt_is_at()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
--- no_error_log
[error]


=== TEST 74: Validator.opt_is_at specific time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_at()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, now=956354999, future=956355000 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "now", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a positive numeric value.
true
'past' claim is only valid at Fri, 21 Apr 2000 22:09:58 GMT
true
'future' claim is only valid at Fri, 21 Apr 2000 22:10:00 GMT
--- no_error_log
[error]



=== TEST 75: Validator.opt_is_at specific time and leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(1)
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_at()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, now=956354999, future=956355000 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "now", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
true
--- no_error_log
[error]


=== TEST 76: Validator.is_at
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_at()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a positive numeric value.
'blah' claim is required.
'past' claim is only valid at Fri, 21 Apr 2000 22:09:58 GMT
'future' claim is only valid at Wed, 21 Apr 2100 22:09:58 GMT
--- no_error_log
[error]


