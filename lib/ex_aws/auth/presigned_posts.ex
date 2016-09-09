defmodule ExAws.Auth.PresignedPosts do
  @moduledoc false

  import ExAws.Auth.Utils
  alias ExAws.Auth.Credentials
  alias ExAws.Auth.Signatures
  alias ExAws.Auth.PresignedPosts.Policy

  # def generate_presigned_post(config, bucket_name, key, opts \\ []) do
  #   datetime = Keyword.get(opts, :current_datetime, :calendar.universal_time)
  #   expires_in = Keyword.get(opts, :expires_in, 60 * 60) #seconds
  #
  #   expiration = ExAws.Utils.add_seconds(datetime, expires_in)
  #
  #   presigned_post =
  #     PresignedPost.new
  #     |> PresignedPost.put_field("key", key)
  #     |> PresignedPost.put_field("x-amz-algorithm", "AWS4-HMAC-SHA256")
  #     |> PresignedPost.put_field("x-amz-date", amz_date(datetime))
  #     |> PresignedPost.put_field(
  #         "x-amz-credential", Credentials.generate_credential_v4("s3", config, datetime)
  #       )
  #
  #
  #   # form_fields =
  #   #   form_fields
  #   #   |> put_policy(config, bucket_name, key, expiration)
  #   #   |> put_signature(config, datetime)
  #
  #   %{
  #     url: "#{config.scheme}#{bucket_name}.#{config.host}",
  #     form_fields: PresignedPost.fields_with_signature(presigned_post)
  #   }
  # end

  def generate_presigned_post(config, bucket_name, key, opts \\ []) do
    datetime = Keyword.get(opts, :current_datetime, :calendar.universal_time)
    expires_in = Keyword.get(opts, :expires_in, 60 * 60) #seconds

    expiration = ExAws.Utils.add_seconds(datetime, expires_in)

    form_fields = %{
      "key" => key,
      "x-amz-algorithm" => "AWS4-HMAC-SHA256",
      "x-amz-date" => amz_date(datetime),
      "x-amz-credential" => Credentials.generate_credential_v4("s3", config, datetime),
    }

    form_fields =
      form_fields
      |> put_policy(config, bucket_name, key, expiration)
      |> put_signature(config, datetime)

    %{
      url: "#{config.scheme}#{bucket_name}.#{config.host}",
      form_fields: form_fields
    }
  end


  defp put_policy(post_fields, config, bucket_name, key, expiration) do
    encoded_policy =
      post_fields
      |> generate_policy(bucket_name, key, expiration)
      |> Policy.encode(config)

    Map.put(post_fields, "policy", encoded_policy)
  end

  defp generate_policy(post_fields, bucket_name, key, expiration) do
    policy =
      Policy.new
      |> Policy.set_expiration(expiration)
      |> Policy.add_condition(%{"bucket" => bucket_name})
      |> Policy.add_condition(["starts-with", "$key", "#{Path.dirname(key)}/"])

    policy =
      post_fields
      |> Map.to_list
      |> Keyword.drop(["AWSAccessKeyId", "key"])
      |> List.keysort(0)
      |> Enum.reduce(policy, fn ({field_name, value}, policy_acc) ->
        Policy.add_condition(policy_acc, %{field_name => value})
      end)
  end

  defp put_signature(%{"policy"=> string_to_sign} = form_fields, config, datetime) do
    signature = Signatures.generate_signature_v4("s3", config, datetime, string_to_sign)

    Map.put(form_fields, "x-amz-signature", signature)
  end
end
