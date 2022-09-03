namespace Paseto.Serializers
{
    using System;
    using System.Text.Json;
    using System.Text.Json.Serialization;

    /// <summary>
    /// JSON serializer using System.Text.Json implementation.
    /// </summary>
    public sealed class TextJsonSerializer : IJsonSerializer
    {
        private readonly JsonSerializerOptions _serializerOptions;

        /// <summary>
        /// Creates a new instance of <see cref="TextJsonSerializer" />.
        /// </summary>
        /// <remarks>Uses <see cref="JsonSerializer.CreateDefault()" /> as internal serializer.</remarks>
        public TextJsonSerializer() : this(new JsonSerializerOptions(new JsonSerializerDefaults())) { }

        /// <summary>
        /// Creates a new instance of <see cref="TextJsonSerializer" />.
        /// </summary>
        /// <param name="serializer">Internal <see cref="JsonSerializer" /> to use for serialization.</param>
        public TextJsonSerializer(JsonSerializerOptions serializerOptions)
        {
            _serializerOptions = serializerOptions ?? throw new ArgumentNullException(nameof(serializerOptions));
            _serializerOptions.Converters.Add(new ObjectJsonConverter());
        }

        /// <inheritdoc />
        public string Serialize(object obj) => JsonSerializer.Serialize(obj, _serializerOptions);

        /// <inheritdoc />
        public T Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, _serializerOptions);
    }

    public class ObjectJsonConverter : JsonConverter<object>
    {
        public override object Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) => reader.TokenType switch
            {
                JsonTokenType.True => true,
                JsonTokenType.False => false,
                JsonTokenType.Number when reader.TryGetInt64(out long l) => l,
                JsonTokenType.Number => reader.GetDouble(),
                JsonTokenType.String when reader.TryGetDateTime(out DateTime datetime) => datetime,
                JsonTokenType.String => reader.GetString()!,
                _ => JsonDocument.ParseValue(ref reader).RootElement.Clone()
            };

        public override void Write(
            Utf8JsonWriter writer,
            object objectToWrite,
            JsonSerializerOptions options) =>
            JsonSerializer.Serialize(writer, objectToWrite, objectToWrite.GetType(), options);

    }
}