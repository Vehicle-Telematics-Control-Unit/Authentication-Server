using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace AuthenticationServer.Migrations
{
    /// <inheritdoc />
    public partial class fixedIpAddress : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AspNetRoles",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    NormalizedName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUsers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    UserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    NormalizedUserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    NormalizedEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    EmailConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                    PasswordHash = table.Column<string>(type: "text", nullable: true),
                    SecurityStamp = table.Column<string>(type: "text", nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "text", nullable: true),
                    PhoneNumber = table.Column<string>(type: "text", nullable: true),
                    PhoneNumberConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                    TwoFactorEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    LockoutEnd = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LockoutEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    AccessFailedCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ObdCodes",
                columns: table => new
                {
                    ObdCode = table.Column<string[]>(type: "character(5)[]", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false),
                    isGeneric = table.Column<bool>(type: "boolean", nullable: false, defaultValueSql: "true")
                },
                constraints: table =>
                {
                    table.PrimaryKey("ObdCodes_pkey", x => x.ObdCode);
                });

            migrationBuilder.CreateTable(
                name: "ObdFaultAreaCodes",
                columns: table => new
                {
                    AreaId = table.Column<char>(type: "character(1)", maxLength: 1, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("ObdFaultAreaCodes_pkey", x => new { x.AreaId, x.Description });
                });

            migrationBuilder.CreateTable(
                name: "ObdSubSystemCodes",
                columns: table => new
                {
                    SubsystemId = table.Column<char>(type: "character(1)", maxLength: 1, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("ObdSubSystemCodes_pkey", x => x.SubsystemId);
                });

            migrationBuilder.CreateTable(
                name: "RequestStatuses",
                columns: table => new
                {
                    StatusId = table.Column<long>(type: "bigint", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("RequestStatuses_pkey", x => x.StatusId);
                });

            migrationBuilder.CreateTable(
                name: "SoftwareVersion",
                columns: table => new
                {
                    VersionId = table.Column<long>(type: "bigint", nullable: false),
                    RXWIN = table.Column<string>(type: "text", nullable: false),
                    CreationTimeStamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PreviousVersion = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("SoftwareVersion_pkey", x => x.VersionId);
                    table.ForeignKey(
                        name: "SoftwareVersion_Unirary",
                        column: x => x.PreviousVersion,
                        principalTable: "SoftwareVersion",
                        principalColumn: "VersionId");
                });

            migrationBuilder.CreateTable(
                name: "AspNetRoleClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    RoleId = table.Column<string>(type: "text", nullable: false),
                    ClaimType = table.Column<string>(type: "text", nullable: true),
                    ClaimValue = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    ClaimType = table.Column<string>(type: "text", nullable: true),
                    ClaimValue = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetUserClaims_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserLogins",
                columns: table => new
                {
                    LoginProvider = table.Column<string>(type: "text", nullable: false),
                    ProviderKey = table.Column<string>(type: "text", nullable: false),
                    ProviderDisplayName = table.Column<string>(type: "text", nullable: true),
                    UserId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserLogins", x => new { x.LoginProvider, x.ProviderKey });
                    table.ForeignKey(
                        name: "FK_AspNetUserLogins_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserRoles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "text", nullable: false),
                    RoleId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserTokens",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "text", nullable: false),
                    LoginProvider = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    Value = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                    table.ForeignKey(
                        name: "FK_AspNetUserTokens_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ContactMethods",
                columns: table => new
                {
                    Type = table.Column<int>(type: "integer", nullable: false),
                    Value = table.Column<string>(type: "text", nullable: false),
                    UserID = table.Column<string>(type: "text", nullable: false),
                    isPrimary = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("Contact_methods_pkey", x => new { x.Type, x.Value, x.UserID });
                    table.ForeignKey(
                        name: "ContactMethods_AspNetUsers",
                        column: x => x.UserID,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Device",
                columns: table => new
                {
                    DeviceId = table.Column<long>(type: "bigint", nullable: false),
                    UserID = table.Column<string>(type: "text", nullable: false),
                    LastLoginTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: true, defaultValueSql: "now()"),
                    IpAddress = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("Device_pkey", x => x.DeviceId);
                    table.ForeignKey(
                        name: "Devices_AspNetUsers",
                        column: x => x.UserID,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "TCU",
                columns: table => new
                {
                    TcuId = table.Column<long>(type: "bigint", nullable: false),
                    IpAddress = table.Column<string[]>(type: "character varying(15)[]", nullable: true),
                    VIN = table.Column<string[]>(type: "character varying(17)[]", nullable: false),
                    CurrentVersionId = table.Column<long>(type: "bigint", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("TCU_pkey", x => x.TcuId);
                    table.ForeignKey(
                        name: "TCU_AspNetUsers",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "TCU_SoftwareVersion",
                        column: x => x.CurrentVersionId,
                        principalTable: "SoftwareVersion",
                        principalColumn: "VersionId");
                });

            migrationBuilder.CreateTable(
                name: "Alerts",
                columns: table => new
                {
                    TcuId = table.Column<long>(type: "bigint", nullable: false),
                    ObdCode = table.Column<string[]>(type: "character(5)[]", nullable: false),
                    LogTimeStamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("Alerts_pkey", x => new { x.LogTimeStamp, x.ObdCode, x.TcuId });
                    table.ForeignKey(
                        name: "Alert_ObdCodes",
                        column: x => x.ObdCode,
                        principalTable: "ObdCodes",
                        principalColumn: "ObdCode");
                    table.ForeignKey(
                        name: "Alert_TCU",
                        column: x => x.TcuId,
                        principalTable: "TCU",
                        principalColumn: "TcuId");
                });

            migrationBuilder.CreateTable(
                name: "ConnectionRequests",
                columns: table => new
                {
                    TcuId = table.Column<long>(type: "bigint", nullable: false),
                    DeviceId = table.Column<long>(type: "bigint", nullable: false),
                    CreationTimeStamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    VerificationTimeStamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Token = table.Column<string>(type: "text", nullable: false),
                    StatusId = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("ConnectionRequests_pkey", x => new { x.TcuId, x.DeviceId, x.CreationTimeStamp });
                    table.ForeignKey(
                        name: "ConnectionRequest_Device",
                        column: x => x.DeviceId,
                        principalTable: "Device",
                        principalColumn: "DeviceId");
                    table.ForeignKey(
                        name: "ConnectionRequest_RequestStatuses",
                        column: x => x.StatusId,
                        principalTable: "RequestStatuses",
                        principalColumn: "StatusId");
                    table.ForeignKey(
                        name: "ConnectionRequest_TCU",
                        column: x => x.TcuId,
                        principalTable: "TCU",
                        principalColumn: "TcuId");
                });

            migrationBuilder.CreateTable(
                name: "DevicesTcu",
                columns: table => new
                {
                    DeviceId = table.Column<long>(type: "bigint", nullable: false),
                    TcuId = table.Column<long>(type: "bigint", nullable: false),
                    isPrimary = table.Column<bool>(type: "boolean", nullable: false),
                    isActive = table.Column<bool>(type: "boolean", nullable: false, defaultValueSql: "true")
                },
                constraints: table =>
                {
                    table.PrimaryKey("DevicesTcu_pkey", x => new { x.DeviceId, x.TcuId });
                    table.ForeignKey(
                        name: "Device_fkey",
                        column: x => x.DeviceId,
                        principalTable: "Device",
                        principalColumn: "DeviceId");
                    table.ForeignKey(
                        name: "TCU_fkey",
                        column: x => x.TcuId,
                        principalTable: "TCU",
                        principalColumn: "TcuId");
                });

            migrationBuilder.CreateTable(
                name: "LockRequests",
                columns: table => new
                {
                    TcuId = table.Column<long>(type: "bigint", nullable: false),
                    DeviceId = table.Column<long>(type: "bigint", nullable: false),
                    CreationTimeStamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    StatusId = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("LockRequests_pkey", x => new { x.TcuId, x.DeviceId, x.CreationTimeStamp });
                    table.ForeignKey(
                        name: "LockRequest_Device",
                        column: x => x.DeviceId,
                        principalTable: "Device",
                        principalColumn: "DeviceId");
                    table.ForeignKey(
                        name: "LockRequest_RequestStatuses",
                        column: x => x.StatusId,
                        principalTable: "RequestStatuses",
                        principalColumn: "StatusId");
                    table.ForeignKey(
                        name: "LockRequest_TCU",
                        column: x => x.TcuId,
                        principalTable: "TCU",
                        principalColumn: "TcuId");
                });

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_ObdCode",
                table: "Alerts",
                column: "ObdCode");

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_TcuId",
                table: "Alerts",
                column: "TcuId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleClaims_RoleId",
                table: "AspNetRoleClaims",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "AspNetRoles",
                column: "NormalizedName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserClaims_UserId",
                table: "AspNetUserClaims",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserLogins_UserId",
                table: "AspNetUserLogins",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserRoles_RoleId",
                table: "AspNetUserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "AspNetUsers",
                column: "NormalizedUserName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionRequests_DeviceId",
                table: "ConnectionRequests",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionRequests_StatusId",
                table: "ConnectionRequests",
                column: "StatusId");

            migrationBuilder.CreateIndex(
                name: "IX_ContactMethods_UserID",
                table: "ContactMethods",
                column: "UserID");

            migrationBuilder.CreateIndex(
                name: "IX_Device_UserID",
                table: "Device",
                column: "UserID");

            migrationBuilder.CreateIndex(
                name: "IX_DevicesTcu_TcuId",
                table: "DevicesTcu",
                column: "TcuId");

            migrationBuilder.CreateIndex(
                name: "IX_LockRequests_DeviceId",
                table: "LockRequests",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_LockRequests_StatusId",
                table: "LockRequests",
                column: "StatusId");

            migrationBuilder.CreateIndex(
                name: "IX_SoftwareVersion_PreviousVersion",
                table: "SoftwareVersion",
                column: "PreviousVersion");

            migrationBuilder.CreateIndex(
                name: "IX_TCU_CurrentVersionId",
                table: "TCU",
                column: "CurrentVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_TCU_UserId",
                table: "TCU",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Alerts");

            migrationBuilder.DropTable(
                name: "AspNetRoleClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserLogins");

            migrationBuilder.DropTable(
                name: "AspNetUserRoles");

            migrationBuilder.DropTable(
                name: "AspNetUserTokens");

            migrationBuilder.DropTable(
                name: "ConnectionRequests");

            migrationBuilder.DropTable(
                name: "ContactMethods");

            migrationBuilder.DropTable(
                name: "DevicesTcu");

            migrationBuilder.DropTable(
                name: "LockRequests");

            migrationBuilder.DropTable(
                name: "ObdFaultAreaCodes");

            migrationBuilder.DropTable(
                name: "ObdSubSystemCodes");

            migrationBuilder.DropTable(
                name: "ObdCodes");

            migrationBuilder.DropTable(
                name: "AspNetRoles");

            migrationBuilder.DropTable(
                name: "Device");

            migrationBuilder.DropTable(
                name: "RequestStatuses");

            migrationBuilder.DropTable(
                name: "TCU");

            migrationBuilder.DropTable(
                name: "AspNetUsers");

            migrationBuilder.DropTable(
                name: "SoftwareVersion");
        }
    }
}
