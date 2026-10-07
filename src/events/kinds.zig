//! The target types: config subsystem name, ARN type, keys, and constructor.
const std = @import("std");
const target = @import("target.zig");

pub const Kind = struct {
    /// Config subsystem, e.g. "notify_webhook" or "audit_kafka".
    subsys: []const u8,
    /// ARN type for notify targets ("webhook", "postgresql", ...).
    arn_type: []const u8,
    /// Env name part: MINIO_NOTIFY_<ENV>_<KEY>[_<ID>].
    env: []const u8,
    keys: []const []const u8,
    create: *const fn (gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client,
    audit: bool = false,
};

const webhook = @import("webhook.zig");
const kafka = @import("kafka.zig");
const nats = @import("nats.zig");
const mqtt = @import("mqtt.zig");
const redis = @import("redis.zig");
const postgres = @import("postgres.zig");
const mysql = @import("mysql.zig");
const amqp = @import("amqp.zig");
const pulsar = @import("pulsar.zig");
const elasticsearch = @import("elasticsearch.zig");
const nsq = @import("nsq.zig");

pub const all = [_]Kind{
    .{ .subsys = "notify_webhook", .arn_type = "webhook", .env = "WEBHOOK", .keys = &webhook.keys, .create = webhook.create },
    .{ .subsys = "notify_kafka", .arn_type = "kafka", .env = "KAFKA", .keys = &kafka.keys, .create = kafka.create },
    .{ .subsys = "notify_nats", .arn_type = "nats", .env = "NATS", .keys = &nats.keys, .create = nats.create },
    .{ .subsys = "notify_mqtt", .arn_type = "mqtt", .env = "MQTT", .keys = &mqtt.keys, .create = mqtt.create },
    .{ .subsys = "notify_redis", .arn_type = "redis", .env = "REDIS", .keys = &redis.keys, .create = redis.create },
    .{ .subsys = "notify_postgres", .arn_type = "postgresql", .env = "POSTGRES", .keys = &postgres.keys, .create = postgres.create },
    .{ .subsys = "notify_mysql", .arn_type = "mysql", .env = "MYSQL", .keys = &mysql.keys, .create = mysql.create },
    .{ .subsys = "notify_amqp", .arn_type = "amqp", .env = "AMQP", .keys = &amqp.keys, .create = amqp.create },
    .{ .subsys = "notify_elasticsearch", .arn_type = "elasticsearch", .env = "ELASTICSEARCH", .keys = &elasticsearch.keys, .create = elasticsearch.create },
    .{ .subsys = "notify_nsq", .arn_type = "nsq", .env = "NSQ", .keys = &nsq.keys, .create = nsq.create },
    .{ .subsys = "notify_pulsar", .arn_type = "pulsar", .env = "PULSAR", .keys = &pulsar.keys, .create = pulsar.create },
    .{ .subsys = "audit_webhook", .arn_type = "", .env = "WEBHOOK", .keys = &webhook.keys, .create = webhook.create, .audit = true },
    .{ .subsys = "audit_kafka", .arn_type = "", .env = "KAFKA", .keys = &kafka.keys, .create = kafka.create, .audit = true },
};

pub fn bySubsys(name: []const u8) ?*const Kind {
    for (&all) |*k| if (std.mem.eql(u8, k.subsys, name)) return k;
    return null;
}

pub fn byArnType(name: []const u8) ?*const Kind {
    for (&all) |*k| if (!k.audit and std.mem.eql(u8, k.arn_type, name)) return k;
    return null;
}

/// Keys every target accepts besides its own.
pub const common_keys = [_][]const u8{ "enable", "queue_dir", "queue_limit", "comment" };

pub fn validKey(k: *const Kind, key: []const u8) bool {
    for (common_keys) |c| if (std.mem.eql(u8, c, key)) return true;
    for (k.keys) |c| if (std.mem.eql(u8, c, key)) return true;
    return false;
}

test {
    _ = webhook;
    _ = kafka;
    _ = nats;
    _ = mqtt;
    _ = redis;
    _ = postgres;
    _ = mysql;
    _ = amqp;
    _ = pulsar;
    _ = elasticsearch;
    _ = nsq;
}
