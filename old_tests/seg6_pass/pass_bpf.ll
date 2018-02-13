; ModuleID = 'pass_bpf.c'
source_filename = "pass_bpf.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.ip6_srh_t = type { i8, i8, i8, i8, i8, i8, i16, [0 x %struct.in6_addr] }
%struct.in6_addr = type { i64, i64 }
%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32 }
%struct.ip6_t = type { i32, i16, i8, i8, i64, i64, i64, i64 }

@__license = global [4 x i8] c"GPL\00", section "license", align 1, !dbg !0
@llvm.used = appending global [8 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @__license, i32 0, i32 0), i8* bitcast (i32 (%struct.__sk_buff*)* @do_alert to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @do_drop to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @do_end_b6 to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @do_end_t to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @do_end_x to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @do_inc to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @do_pass to i8*)], section "llvm.metadata"

; Function Attrs: nounwind readonly uwtable
define %struct.ip6_srh_t* @get_srh(%struct.__sk_buff* nocapture readonly) local_unnamed_addr #0 !dbg !119 {
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !123, metadata !DIExpression()), !dbg !146
  %2 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16, !dbg !147
  %3 = load i32, i32* %2, align 4, !dbg !147, !tbaa !148
  %4 = zext i32 %3 to i64, !dbg !153
  %5 = inttoptr i64 %4 to i8*, !dbg !154
  tail call void @llvm.dbg.value(metadata i8* %5, metadata !125, metadata !DIExpression()), !dbg !155
  %6 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15, !dbg !156
  %7 = load i32, i32* %6, align 4, !dbg !156, !tbaa !157
  %8 = zext i32 %7 to i64, !dbg !158
  %9 = inttoptr i64 %8 to i8*, !dbg !159
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !126, metadata !DIExpression()), !dbg !160
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !124, metadata !DIExpression()), !dbg !161
  %10 = getelementptr i8, i8* %9, i64 1, !dbg !162
  %11 = icmp ugt i8* %10, %5, !dbg !164
  br i1 %11, label %33, label %12, !dbg !165

; <label>:12:                                     ; preds = %1
  %13 = load i8, i8* %9, align 1, !dbg !166, !tbaa !168
  %14 = and i8 %13, -16, !dbg !169
  %15 = icmp eq i8 %14, 96, !dbg !169
  br i1 %15, label %16, label %33, !dbg !170

; <label>:16:                                     ; preds = %12
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !141, metadata !DIExpression()), !dbg !171
  %17 = getelementptr i8, i8* %9, i64 40, !dbg !171
  tail call void @llvm.dbg.value(metadata i8* %17, metadata !126, metadata !DIExpression()), !dbg !160
  tail call void @llvm.dbg.value(metadata %struct.ip6_t* %20, metadata !127, metadata !DIExpression()), !dbg !172
  %18 = icmp ugt i8* %17, %5, !dbg !173
  br i1 %18, label %33, label %19, !dbg !175

; <label>:19:                                     ; preds = %16
  %20 = inttoptr i64 %8 to %struct.ip6_t*, !dbg !176
  %21 = getelementptr inbounds %struct.ip6_t, %struct.ip6_t* %20, i64 0, i32 2, !dbg !177
  %22 = load i8, i8* %21, align 1, !dbg !177, !tbaa !179
  %23 = icmp ne i8 %22, 43, !dbg !183
  %24 = getelementptr i8, i8* %9, i64 48, !dbg !184
  %25 = icmp ugt i8* %24, %5, !dbg !186
  %26 = or i1 %25, %23, !dbg !187
  tail call void @llvm.dbg.value(metadata %struct.ip6_srh_t* %28, metadata !143, metadata !DIExpression()), !dbg !188
  br i1 %26, label %33, label %27, !dbg !187

; <label>:27:                                     ; preds = %19
  %28 = bitcast i8* %17 to %struct.ip6_srh_t*, !dbg !189
  %29 = getelementptr inbounds i8, i8* %9, i64 42, !dbg !190
  %30 = load i8, i8* %29, align 1, !dbg !190, !tbaa !192
  %31 = icmp eq i8 %30, 4, !dbg !194
  %32 = select i1 %31, %struct.ip6_srh_t* %28, %struct.ip6_srh_t* null, !dbg !195
  br label %33, !dbg !195

; <label>:33:                                     ; preds = %19, %16, %27, %12, %1
  %34 = phi %struct.ip6_srh_t* [ null, %1 ], [ null, %12 ], [ null, %16 ], [ null, %19 ], [ %32, %27 ]
  ret %struct.ip6_srh_t* %34, !dbg !196
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: nounwind readnone uwtable
define i32 @do_pass(%struct.__sk_buff* nocapture readnone) #2 section "pass" !dbg !197 {
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !201, metadata !DIExpression()), !dbg !202
  ret i32 0, !dbg !203
}

; Function Attrs: nounwind readnone uwtable
define i32 @do_drop(%struct.__sk_buff* nocapture readnone) #2 section "drop" !dbg !204 {
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !206, metadata !DIExpression()), !dbg !207
  ret i32 2, !dbg !208
}

; Function Attrs: nounwind uwtable
define i32 @do_inc(%struct.__sk_buff*) #3 section "inc" !dbg !209 {
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !211, metadata !DIExpression()), !dbg !216
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !123, metadata !DIExpression()), !dbg !217
  %2 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16, !dbg !219
  %3 = load i32, i32* %2, align 4, !dbg !219, !tbaa !148
  %4 = zext i32 %3 to i64, !dbg !220
  %5 = inttoptr i64 %4 to i8*, !dbg !221
  tail call void @llvm.dbg.value(metadata i8* %5, metadata !125, metadata !DIExpression()), !dbg !222
  %6 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15, !dbg !223
  %7 = load i32, i32* %6, align 4, !dbg !223, !tbaa !157
  %8 = zext i32 %7 to i64, !dbg !224
  %9 = inttoptr i64 %8 to i8*, !dbg !225
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !126, metadata !DIExpression()), !dbg !226
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !124, metadata !DIExpression()), !dbg !227
  %10 = getelementptr i8, i8* %9, i64 1, !dbg !228
  %11 = icmp ugt i8* %10, %5, !dbg !229
  br i1 %11, label %45, label %12, !dbg !230

; <label>:12:                                     ; preds = %1
  %13 = load i8, i8* %9, align 1, !dbg !231, !tbaa !168
  %14 = and i8 %13, -16, !dbg !232
  %15 = icmp eq i8 %14, 96, !dbg !232
  br i1 %15, label %16, label %45, !dbg !233

; <label>:16:                                     ; preds = %12
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !141, metadata !DIExpression()), !dbg !234
  %17 = getelementptr i8, i8* %9, i64 40, !dbg !234
  tail call void @llvm.dbg.value(metadata i8* %17, metadata !126, metadata !DIExpression()), !dbg !226
  %18 = icmp ugt i8* %17, %5, !dbg !235
  br i1 %18, label %45, label %19, !dbg !236

; <label>:19:                                     ; preds = %16
  %20 = inttoptr i64 %8 to %struct.ip6_t*, !dbg !237
  %21 = getelementptr inbounds %struct.ip6_t, %struct.ip6_t* %20, i64 0, i32 2, !dbg !238
  %22 = load i8, i8* %21, align 1, !dbg !238, !tbaa !179
  %23 = icmp ne i8 %22, 43, !dbg !239
  %24 = getelementptr i8, i8* %9, i64 48, !dbg !240
  %25 = icmp ugt i8* %24, %5, !dbg !241
  %26 = or i1 %25, %23, !dbg !242
  br i1 %26, label %45, label %27, !dbg !242

; <label>:27:                                     ; preds = %19
  %28 = getelementptr inbounds i8, i8* %9, i64 42, !dbg !243
  %29 = load i8, i8* %28, align 1, !dbg !243, !tbaa !192
  %30 = icmp ne i8 %29, 4, !dbg !244
  %31 = icmp eq i8* %17, null, !dbg !245
  %32 = or i1 %31, %30
  tail call void @llvm.dbg.value(metadata i8* %17, metadata !212, metadata !DIExpression()), !dbg !247
  br i1 %32, label %45, label %33

; <label>:33:                                     ; preds = %27
  %34 = getelementptr inbounds i8, i8* %9, i64 46, !dbg !248
  %35 = bitcast i8* %34 to i16*, !dbg !248
  %36 = load i16, i16* %35, align 1, !dbg !248, !tbaa !249
  %37 = tail call i16 @llvm.bswap.i16(i16 %36)
  %38 = add i16 %37, 1, !dbg !250
  %39 = zext i16 %38 to i32, !dbg !250
  %40 = shl nuw nsw i32 %39, 8, !dbg !250
  %41 = lshr i32 %39, 8, !dbg !250
  %42 = and i32 %40, 65280, !dbg !251
  %43 = or i32 %42, %41, !dbg !251
  %44 = tail call i32 inttoptr (i64 59 to i32 (%struct.__sk_buff*, i8, i32)*)(%struct.__sk_buff* nonnull %0, i8 zeroext 1, i32 %43) #7, !dbg !252
  br label %45

; <label>:45:                                     ; preds = %27, %19, %16, %12, %1, %33
  %46 = phi i32 [ 0, %33 ], [ 2, %1 ], [ 2, %12 ], [ 2, %16 ], [ 2, %19 ], [ 2, %27 ]
  ret i32 %46, !dbg !253
}

; Function Attrs: nounwind uwtable
define i32 @do_alert(%struct.__sk_buff*) #3 section "alert" !dbg !254 {
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !256, metadata !DIExpression()), !dbg !258
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !123, metadata !DIExpression()), !dbg !259
  %2 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16, !dbg !261
  %3 = load i32, i32* %2, align 4, !dbg !261, !tbaa !148
  %4 = zext i32 %3 to i64, !dbg !262
  %5 = inttoptr i64 %4 to i8*, !dbg !263
  tail call void @llvm.dbg.value(metadata i8* %5, metadata !125, metadata !DIExpression()), !dbg !264
  %6 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15, !dbg !265
  %7 = load i32, i32* %6, align 4, !dbg !265, !tbaa !157
  %8 = zext i32 %7 to i64, !dbg !266
  %9 = inttoptr i64 %8 to i8*, !dbg !267
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !126, metadata !DIExpression()), !dbg !268
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !124, metadata !DIExpression()), !dbg !269
  %10 = getelementptr i8, i8* %9, i64 1, !dbg !270
  %11 = icmp ugt i8* %10, %5, !dbg !271
  br i1 %11, label %39, label %12, !dbg !272

; <label>:12:                                     ; preds = %1
  %13 = load i8, i8* %9, align 1, !dbg !273, !tbaa !168
  %14 = and i8 %13, -16, !dbg !274
  %15 = icmp eq i8 %14, 96, !dbg !274
  br i1 %15, label %16, label %39, !dbg !275

; <label>:16:                                     ; preds = %12
  tail call void @llvm.dbg.value(metadata i8* %9, metadata !141, metadata !DIExpression()), !dbg !276
  %17 = getelementptr i8, i8* %9, i64 40, !dbg !276
  tail call void @llvm.dbg.value(metadata i8* %17, metadata !126, metadata !DIExpression()), !dbg !268
  %18 = icmp ugt i8* %17, %5, !dbg !277
  br i1 %18, label %39, label %19, !dbg !278

; <label>:19:                                     ; preds = %16
  %20 = inttoptr i64 %8 to %struct.ip6_t*, !dbg !279
  %21 = getelementptr inbounds %struct.ip6_t, %struct.ip6_t* %20, i64 0, i32 2, !dbg !280
  %22 = load i8, i8* %21, align 1, !dbg !280, !tbaa !179
  %23 = icmp ne i8 %22, 43, !dbg !281
  %24 = getelementptr i8, i8* %9, i64 48, !dbg !282
  %25 = icmp ugt i8* %24, %5, !dbg !283
  %26 = or i1 %25, %23, !dbg !284
  br i1 %26, label %39, label %27, !dbg !284

; <label>:27:                                     ; preds = %19
  %28 = getelementptr inbounds i8, i8* %9, i64 42, !dbg !285
  %29 = load i8, i8* %28, align 1, !dbg !285, !tbaa !192
  %30 = icmp ne i8 %29, 4, !dbg !286
  %31 = icmp eq i8* %17, null, !dbg !287
  %32 = or i1 %31, %30
  tail call void @llvm.dbg.value(metadata i8* %17, metadata !257, metadata !DIExpression()), !dbg !289
  br i1 %32, label %39, label %33

; <label>:33:                                     ; preds = %27
  %34 = getelementptr inbounds i8, i8* %9, i64 45, !dbg !290
  %35 = load i8, i8* %34, align 1, !dbg !290, !tbaa !291
  %36 = or i8 %35, 16, !dbg !292
  %37 = zext i8 %36 to i32, !dbg !292
  %38 = tail call i32 inttoptr (i64 59 to i32 (%struct.__sk_buff*, i8, i32)*)(%struct.__sk_buff* nonnull %0, i8 zeroext 0, i32 %37) #7, !dbg !293
  br label %39, !dbg !294

; <label>:39:                                     ; preds = %27, %19, %16, %12, %1, %33
  %40 = phi i32 [ 0, %33 ], [ 2, %1 ], [ 2, %12 ], [ 2, %16 ], [ 2, %19 ], [ 2, %27 ]
  ret i32 %40, !dbg !295
}

; Function Attrs: nounwind uwtable
define i32 @do_end_x(%struct.__sk_buff*) #3 section "end_x" !dbg !296 {
  %2 = alloca %struct.in6_addr, align 8
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !298, metadata !DIExpression()), !dbg !302
  %3 = bitcast %struct.in6_addr* %2 to i8*, !dbg !303
  call void @llvm.lifetime.start.p0i8(i64 16, i8* nonnull %3) #7, !dbg !303
  tail call void @llvm.dbg.value(metadata i64 -269653027688808448, metadata !300, metadata !DIExpression()), !dbg !304
  tail call void @llvm.dbg.value(metadata i64 1, metadata !301, metadata !DIExpression()), !dbg !305
  %4 = getelementptr inbounds %struct.in6_addr, %struct.in6_addr* %2, i64 0, i32 1, !dbg !306
  store i64 72057594037927936, i64* %4, align 8, !dbg !307, !tbaa !308
  %5 = getelementptr inbounds %struct.in6_addr, %struct.in6_addr* %2, i64 0, i32 0, !dbg !310
  store i64 17148, i64* %5, align 8, !dbg !311, !tbaa !312
  tail call void @llvm.dbg.value(metadata %struct.in6_addr* %2, metadata !299, metadata !DIExpression()), !dbg !313
  %6 = call i32 inttoptr (i64 62 to i32 (%struct.__sk_buff*, %struct.in6_addr*)*)(%struct.__sk_buff* %0, %struct.in6_addr* nonnull %2) #7, !dbg !314
  call void @llvm.lifetime.end.p0i8(i64 16, i8* nonnull %3) #7, !dbg !315
  ret i32 7, !dbg !316
}

; Function Attrs: nounwind uwtable
define i32 @do_end_t(%struct.__sk_buff*) #3 section "end_t" !dbg !317 {
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !319, metadata !DIExpression()), !dbg !320
  %2 = tail call i32 inttoptr (i64 63 to i32 (%struct.__sk_buff*, i32)*)(%struct.__sk_buff* %0, i32 42) #7, !dbg !321
  ret i32 7, !dbg !322
}

; Function Attrs: noreturn nounwind uwtable
define i32 @do_end_b6(%struct.__sk_buff* nocapture readnone) #4 section "end_b6" !dbg !323 {
  tail call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !325, metadata !DIExpression()), !dbg !335
  tail call void @llvm.dbg.value(metadata %struct.ip6_srh_t* undef, metadata !330, metadata !DIExpression()), !dbg !336
  tail call void @llvm.dbg.value(metadata i8 4, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata i8 4, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata i8 1, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata i8 1, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata i8 0, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata i16 0, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata %struct.in6_addr* undef, metadata !331, metadata !DIExpression()), !dbg !338
  tail call void @llvm.dbg.value(metadata %struct.in6_addr* undef, metadata !332, metadata !DIExpression()), !dbg !339
  tail call void @llvm.dbg.value(metadata i64 -269653027688808448, metadata !333, metadata !DIExpression()), !dbg !340
  tail call void @llvm.dbg.value(metadata i64 2, metadata !334, metadata !DIExpression()), !dbg !341
  tail call void @llvm.dbg.value(metadata i64 144115188075855872, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata i64 17148, metadata !326, metadata !DIExpression()), !dbg !337
  tail call void @llvm.dbg.value(metadata i64 1, metadata !334, metadata !DIExpression()), !dbg !341
  tail call void @llvm.trap(), !dbg !342
  unreachable
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.value(metadata, metadata, metadata) #5

; Function Attrs: noreturn nounwind
declare void @llvm.trap() #6

; Function Attrs: nounwind readnone speculatable
declare i16 @llvm.bswap.i16(i16) #5

attributes #0 = { nounwind readonly uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { nounwind readnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { noreturn nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { nounwind readnone speculatable }
attributes #6 = { noreturn nounwind }
attributes #7 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!115, !116, !117}
!llvm.ident = !{!118}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "__license", scope: !2, file: !3, line: 124, type: !114, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 6.0.0 (trunk 318052)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !11, globals: !56)
!3 = !DIFile(filename: "pass_bpf.c", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "bpf_ret_code", file: !6, line: 869, size: 32, elements: !7)
!6 = !DIFile(filename: "./bpf.h", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!7 = !{!8, !9, !10}
!8 = !DIEnumerator(name: "BPF_OK", value: 0)
!9 = !DIEnumerator(name: "BPF_DROP", value: 2)
!10 = !DIEnumerator(name: "BPF_REDIRECT", value: 7)
!11 = !{!12, !13, !14, !20, !23, !25, !28, !31, !32, !33, !53, !54}
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!13 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!14 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !15, size: 64)
!15 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint8_t", file: !16, line: 24, baseType: !17)
!16 = !DIFile(filename: "/usr/include/bits/stdint-uintn.h", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint8_t", file: !18, line: 37, baseType: !19)
!18 = !DIFile(filename: "/usr/include/bits/types.h", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!19 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!20 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !21, line: 23, baseType: !22)
!21 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!22 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!23 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !24, line: 24, baseType: !20)
!24 = !DIFile(filename: "/usr/include/linux/types.h", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!25 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint32_t", file: !16, line: 26, baseType: !26)
!26 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint32_t", file: !18, line: 41, baseType: !27)
!27 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!28 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint64_t", file: !16, line: 27, baseType: !29)
!29 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint64_t", file: !18, line: 44, baseType: !30)
!30 = !DIBasicType(name: "long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!31 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !24, line: 26, baseType: !32)
!32 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !21, line: 26, baseType: !27)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ip6_srh_t", file: !35, line: 91, size: 64, elements: !36)
!35 = !DIFile(filename: "./proto.h", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!36 = !{!37, !38, !39, !40, !41, !42, !43, !44}
!37 = !DIDerivedType(tag: DW_TAG_member, name: "nexthdr", scope: !34, file: !35, line: 92, baseType: !19, size: 8)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "hdrlen", scope: !34, file: !35, line: 93, baseType: !19, size: 8, offset: 8)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !34, file: !35, line: 94, baseType: !19, size: 8, offset: 16)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "segments_left", scope: !34, file: !35, line: 95, baseType: !19, size: 8, offset: 24)
!41 = !DIDerivedType(tag: DW_TAG_member, name: "first_segment", scope: !34, file: !35, line: 96, baseType: !19, size: 8, offset: 32)
!42 = !DIDerivedType(tag: DW_TAG_member, name: "flags", scope: !34, file: !35, line: 97, baseType: !19, size: 8, offset: 40)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "tag", scope: !34, file: !35, line: 98, baseType: !22, size: 16, offset: 48)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "segments", scope: !34, file: !35, line: 100, baseType: !45, offset: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !46, elements: !51)
!46 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "in6_addr", file: !35, line: 86, size: 128, elements: !47)
!47 = !{!48, !50}
!48 = !DIDerivedType(tag: DW_TAG_member, name: "hi", scope: !46, file: !35, line: 87, baseType: !49, size: 64)
!49 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "lo", scope: !46, file: !35, line: 88, baseType: !49, size: 64, offset: 64)
!51 = !{!52}
!52 = !DISubrange(count: 0)
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!56 = !{!0, !57, !99, !104, !109}
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(name: "skb_seg6_change_field", scope: !2, file: !59, line: 230, type: !60, isLocal: true, isDefinition: true)
!59 = !DIFile(filename: "./bpf_api.h", directory: "/home/math/Thesis/VM/shared/eBPF-tests/seg6_pass")
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !61, size: 64)
!61 = !DISubroutineType(types: !62)
!62 = !{!63, !64, !15, !25}
!63 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__sk_buff", file: !6, line: 817, size: 1152, elements: !66)
!66 = !{!67, !68, !69, !70, !71, !72, !73, !74, !75, !76, !77, !78, !79, !83, !84, !85, !86, !87, !88, !89, !90, !91, !95, !96, !97, !98}
!67 = !DIDerivedType(tag: DW_TAG_member, name: "len", scope: !65, file: !6, line: 818, baseType: !32, size: 32)
!68 = !DIDerivedType(tag: DW_TAG_member, name: "pkt_type", scope: !65, file: !6, line: 819, baseType: !32, size: 32, offset: 32)
!69 = !DIDerivedType(tag: DW_TAG_member, name: "mark", scope: !65, file: !6, line: 820, baseType: !32, size: 32, offset: 64)
!70 = !DIDerivedType(tag: DW_TAG_member, name: "queue_mapping", scope: !65, file: !6, line: 821, baseType: !32, size: 32, offset: 96)
!71 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !65, file: !6, line: 822, baseType: !32, size: 32, offset: 128)
!72 = !DIDerivedType(tag: DW_TAG_member, name: "vlan_present", scope: !65, file: !6, line: 823, baseType: !32, size: 32, offset: 160)
!73 = !DIDerivedType(tag: DW_TAG_member, name: "vlan_tci", scope: !65, file: !6, line: 824, baseType: !32, size: 32, offset: 192)
!74 = !DIDerivedType(tag: DW_TAG_member, name: "vlan_proto", scope: !65, file: !6, line: 825, baseType: !32, size: 32, offset: 224)
!75 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !65, file: !6, line: 826, baseType: !32, size: 32, offset: 256)
!76 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !65, file: !6, line: 827, baseType: !32, size: 32, offset: 288)
!77 = !DIDerivedType(tag: DW_TAG_member, name: "ifindex", scope: !65, file: !6, line: 828, baseType: !32, size: 32, offset: 320)
!78 = !DIDerivedType(tag: DW_TAG_member, name: "tc_index", scope: !65, file: !6, line: 829, baseType: !32, size: 32, offset: 352)
!79 = !DIDerivedType(tag: DW_TAG_member, name: "cb", scope: !65, file: !6, line: 830, baseType: !80, size: 160, offset: 384)
!80 = !DICompositeType(tag: DW_TAG_array_type, baseType: !32, size: 160, elements: !81)
!81 = !{!82}
!82 = !DISubrange(count: 5)
!83 = !DIDerivedType(tag: DW_TAG_member, name: "hash", scope: !65, file: !6, line: 831, baseType: !32, size: 32, offset: 544)
!84 = !DIDerivedType(tag: DW_TAG_member, name: "tc_classid", scope: !65, file: !6, line: 832, baseType: !32, size: 32, offset: 576)
!85 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !65, file: !6, line: 833, baseType: !32, size: 32, offset: 608)
!86 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !65, file: !6, line: 834, baseType: !32, size: 32, offset: 640)
!87 = !DIDerivedType(tag: DW_TAG_member, name: "napi_id", scope: !65, file: !6, line: 835, baseType: !32, size: 32, offset: 672)
!88 = !DIDerivedType(tag: DW_TAG_member, name: "family", scope: !65, file: !6, line: 838, baseType: !32, size: 32, offset: 704)
!89 = !DIDerivedType(tag: DW_TAG_member, name: "remote_ip4", scope: !65, file: !6, line: 839, baseType: !32, size: 32, offset: 736)
!90 = !DIDerivedType(tag: DW_TAG_member, name: "local_ip4", scope: !65, file: !6, line: 840, baseType: !32, size: 32, offset: 768)
!91 = !DIDerivedType(tag: DW_TAG_member, name: "remote_ip6", scope: !65, file: !6, line: 841, baseType: !92, size: 128, offset: 800)
!92 = !DICompositeType(tag: DW_TAG_array_type, baseType: !32, size: 128, elements: !93)
!93 = !{!94}
!94 = !DISubrange(count: 4)
!95 = !DIDerivedType(tag: DW_TAG_member, name: "local_ip6", scope: !65, file: !6, line: 842, baseType: !92, size: 128, offset: 928)
!96 = !DIDerivedType(tag: DW_TAG_member, name: "remote_port", scope: !65, file: !6, line: 843, baseType: !32, size: 32, offset: 1056)
!97 = !DIDerivedType(tag: DW_TAG_member, name: "local_port", scope: !65, file: !6, line: 844, baseType: !32, size: 32, offset: 1088)
!98 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !65, file: !6, line: 847, baseType: !32, size: 32, offset: 1120)
!99 = !DIGlobalVariableExpression(var: !100, expr: !DIExpression())
!100 = distinct !DIGlobalVariable(name: "skb_seg6_action_end_x", scope: !2, file: !59, line: 233, type: !101, isLocal: true, isDefinition: true)
!101 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !102, size: 64)
!102 = !DISubroutineType(types: !103)
!103 = !{!63, !64, !53}
!104 = !DIGlobalVariableExpression(var: !105, expr: !DIExpression())
!105 = distinct !DIGlobalVariable(name: "skb_seg6_action_end_t", scope: !2, file: !59, line: 234, type: !106, isLocal: true, isDefinition: true)
!106 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !107, size: 64)
!107 = !DISubroutineType(types: !108)
!108 = !{!63, !64, !25}
!109 = !DIGlobalVariableExpression(var: !110, expr: !DIExpression())
!110 = distinct !DIGlobalVariable(name: "skb_seg6_action_end_b6", scope: !2, file: !59, line: 235, type: !111, isLocal: true, isDefinition: true)
!111 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !112, size: 64)
!112 = !DISubroutineType(types: !113)
!113 = !{!63, !64, !33}
!114 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 32, elements: !93)
!115 = !{i32 2, !"Dwarf Version", i32 4}
!116 = !{i32 2, !"Debug Info Version", i32 3}
!117 = !{i32 1, !"wchar_size", i32 4}
!118 = !{!"clang version 6.0.0 (trunk 318052)"}
!119 = distinct !DISubprogram(name: "get_srh", scope: !3, file: !3, line: 15, type: !120, isLocal: false, isDefinition: true, scopeLine: 15, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !122)
!120 = !DISubroutineType(types: !121)
!121 = !{!33, !64}
!122 = !{!123, !124, !125, !126, !127, !141, !143, !144}
!123 = !DILocalVariable(name: "skb", arg: 1, scope: !119, file: !3, line: 15, type: !64)
!124 = !DILocalVariable(name: "ipver", scope: !119, file: !3, line: 16, type: !14)
!125 = !DILocalVariable(name: "data_end", scope: !119, file: !3, line: 17, type: !12)
!126 = !DILocalVariable(name: "cursor", scope: !119, file: !3, line: 18, type: !12)
!127 = !DILocalVariable(name: "ip", scope: !119, file: !3, line: 28, type: !128)
!128 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !129, size: 64)
!129 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ip6_t", file: !35, line: 73, size: 320, elements: !130)
!130 = !{!131, !132, !133, !134, !135, !136, !137, !138, !139, !140}
!131 = !DIDerivedType(tag: DW_TAG_member, name: "ver", scope: !129, file: !35, line: 74, baseType: !27, size: 4, flags: DIFlagBitField, extraData: i64 0)
!132 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !129, file: !35, line: 75, baseType: !27, size: 8, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!133 = !DIDerivedType(tag: DW_TAG_member, name: "flow_label", scope: !129, file: !35, line: 76, baseType: !27, size: 20, offset: 12, flags: DIFlagBitField, extraData: i64 0)
!134 = !DIDerivedType(tag: DW_TAG_member, name: "payload_len", scope: !129, file: !35, line: 77, baseType: !22, size: 16, offset: 32)
!135 = !DIDerivedType(tag: DW_TAG_member, name: "next_header", scope: !129, file: !35, line: 78, baseType: !19, size: 8, offset: 48)
!136 = !DIDerivedType(tag: DW_TAG_member, name: "hop_limit", scope: !129, file: !35, line: 79, baseType: !19, size: 8, offset: 56)
!137 = !DIDerivedType(tag: DW_TAG_member, name: "src_hi", scope: !129, file: !35, line: 80, baseType: !49, size: 64, offset: 64)
!138 = !DIDerivedType(tag: DW_TAG_member, name: "src_lo", scope: !129, file: !35, line: 81, baseType: !49, size: 64, offset: 128)
!139 = !DIDerivedType(tag: DW_TAG_member, name: "dst_hi", scope: !129, file: !35, line: 82, baseType: !49, size: 64, offset: 192)
!140 = !DIDerivedType(tag: DW_TAG_member, name: "dst_lo", scope: !129, file: !35, line: 83, baseType: !49, size: 64, offset: 256)
!141 = !DILocalVariable(name: "_tmp", scope: !142, file: !3, line: 29, type: !12)
!142 = distinct !DILexicalBlock(scope: !119, file: !3, line: 29, column: 10)
!143 = !DILocalVariable(name: "srh", scope: !119, file: !3, line: 36, type: !33)
!144 = !DILocalVariable(name: "_tmp", scope: !145, file: !3, line: 37, type: !12)
!145 = distinct !DILexicalBlock(scope: !119, file: !3, line: 37, column: 11)
!146 = !DILocation(line: 15, column: 45, scope: !119)
!147 = !DILocation(line: 17, column: 41, scope: !119)
!148 = !{!149, !150, i64 80}
!149 = !{!"__sk_buff", !150, i64 0, !150, i64 4, !150, i64 8, !150, i64 12, !150, i64 16, !150, i64 20, !150, i64 24, !150, i64 28, !150, i64 32, !150, i64 36, !150, i64 40, !150, i64 44, !151, i64 48, !150, i64 68, !150, i64 72, !150, i64 76, !150, i64 80, !150, i64 84, !150, i64 88, !150, i64 92, !150, i64 96, !151, i64 100, !151, i64 116, !150, i64 132, !150, i64 136, !150, i64 140}
!150 = !{!"int", !151, i64 0}
!151 = !{!"omnipotent char", !152, i64 0}
!152 = !{!"Simple C/C++ TBAA"}
!153 = !DILocation(line: 17, column: 30, scope: !119)
!154 = !DILocation(line: 17, column: 22, scope: !119)
!155 = !DILocation(line: 17, column: 11, scope: !119)
!156 = !DILocation(line: 18, column: 41, scope: !119)
!157 = !{!149, !150, i64 76}
!158 = !DILocation(line: 18, column: 30, scope: !119)
!159 = !DILocation(line: 18, column: 22, scope: !119)
!160 = !DILocation(line: 18, column: 11, scope: !119)
!161 = !DILocation(line: 16, column: 14, scope: !119)
!162 = !DILocation(line: 22, column: 23, scope: !163)
!163 = distinct !DILexicalBlock(scope: !119, file: !3, line: 22, column: 9)
!164 = !DILocation(line: 22, column: 40, scope: !163)
!165 = !DILocation(line: 22, column: 9, scope: !119)
!166 = !DILocation(line: 25, column: 10, scope: !167)
!167 = distinct !DILexicalBlock(scope: !119, file: !3, line: 25, column: 9)
!168 = !{!151, !151, i64 0}
!169 = !DILocation(line: 25, column: 23, scope: !167)
!170 = !DILocation(line: 25, column: 9, scope: !119)
!171 = !DILocation(line: 29, column: 10, scope: !142)
!172 = !DILocation(line: 28, column: 19, scope: !119)
!173 = !DILocation(line: 30, column: 34, scope: !174)
!174 = distinct !DILexicalBlock(scope: !119, file: !3, line: 30, column: 9)
!175 = !DILocation(line: 30, column: 9, scope: !119)
!176 = !DILocation(line: 29, column: 10, scope: !119)
!177 = !DILocation(line: 33, column: 13, scope: !178)
!178 = distinct !DILexicalBlock(scope: !119, file: !3, line: 33, column: 9)
!179 = !{!180, !151, i64 6}
!180 = !{!"ip6_t", !150, i64 0, !150, i64 0, !150, i64 1, !181, i64 4, !151, i64 6, !151, i64 7, !182, i64 8, !182, i64 16, !182, i64 24, !182, i64 32}
!181 = !{!"short", !151, i64 0}
!182 = !{!"long long", !151, i64 0}
!183 = !DILocation(line: 33, column: 25, scope: !178)
!184 = !DILocation(line: 38, column: 21, scope: !185)
!185 = distinct !DILexicalBlock(scope: !119, file: !3, line: 38, column: 9)
!186 = !DILocation(line: 38, column: 36, scope: !185)
!187 = !DILocation(line: 33, column: 9, scope: !119)
!188 = !DILocation(line: 36, column: 23, scope: !119)
!189 = !DILocation(line: 37, column: 11, scope: !119)
!190 = !DILocation(line: 41, column: 14, scope: !191)
!191 = distinct !DILexicalBlock(scope: !119, file: !3, line: 41, column: 9)
!192 = !{!193, !151, i64 2}
!193 = !{!"ip6_srh_t", !151, i64 0, !151, i64 1, !151, i64 2, !151, i64 3, !151, i64 4, !151, i64 5, !181, i64 6, !151, i64 8}
!194 = !DILocation(line: 41, column: 19, scope: !191)
!195 = !DILocation(line: 44, column: 5, scope: !119)
!196 = !DILocation(line: 45, column: 1, scope: !119)
!197 = distinct !DISubprogram(name: "do_pass", scope: !3, file: !3, line: 48, type: !198, isLocal: false, isDefinition: true, scopeLine: 48, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !200)
!198 = !DISubroutineType(types: !199)
!199 = !{!63, !64}
!200 = !{!201}
!201 = !DILocalVariable(name: "skb", arg: 1, scope: !197, file: !3, line: 48, type: !64)
!202 = !DILocation(line: 48, column: 31, scope: !197)
!203 = !DILocation(line: 49, column: 5, scope: !197)
!204 = distinct !DISubprogram(name: "do_drop", scope: !3, file: !3, line: 53, type: !198, isLocal: false, isDefinition: true, scopeLine: 53, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !205)
!205 = !{!206}
!206 = !DILocalVariable(name: "skb", arg: 1, scope: !204, file: !3, line: 53, type: !64)
!207 = !DILocation(line: 53, column: 31, scope: !204)
!208 = !DILocation(line: 54, column: 5, scope: !204)
!209 = distinct !DISubprogram(name: "do_inc", scope: !3, file: !3, line: 58, type: !198, isLocal: false, isDefinition: true, scopeLine: 58, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !210)
!210 = !{!211, !212, !213}
!211 = !DILocalVariable(name: "skb", arg: 1, scope: !209, file: !3, line: 58, type: !64)
!212 = !DILocalVariable(name: "srh", scope: !209, file: !3, line: 59, type: !33)
!213 = !DILocalVariable(name: "tag", scope: !209, file: !3, line: 63, type: !214)
!214 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint16_t", file: !16, line: 25, baseType: !215)
!215 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint16_t", file: !18, line: 39, baseType: !22)
!216 = !DILocation(line: 58, column: 30, scope: !209)
!217 = !DILocation(line: 15, column: 45, scope: !119, inlinedAt: !218)
!218 = distinct !DILocation(line: 59, column: 29, scope: !209)
!219 = !DILocation(line: 17, column: 41, scope: !119, inlinedAt: !218)
!220 = !DILocation(line: 17, column: 30, scope: !119, inlinedAt: !218)
!221 = !DILocation(line: 17, column: 22, scope: !119, inlinedAt: !218)
!222 = !DILocation(line: 17, column: 11, scope: !119, inlinedAt: !218)
!223 = !DILocation(line: 18, column: 41, scope: !119, inlinedAt: !218)
!224 = !DILocation(line: 18, column: 30, scope: !119, inlinedAt: !218)
!225 = !DILocation(line: 18, column: 22, scope: !119, inlinedAt: !218)
!226 = !DILocation(line: 18, column: 11, scope: !119, inlinedAt: !218)
!227 = !DILocation(line: 16, column: 14, scope: !119, inlinedAt: !218)
!228 = !DILocation(line: 22, column: 23, scope: !163, inlinedAt: !218)
!229 = !DILocation(line: 22, column: 40, scope: !163, inlinedAt: !218)
!230 = !DILocation(line: 22, column: 9, scope: !119, inlinedAt: !218)
!231 = !DILocation(line: 25, column: 10, scope: !167, inlinedAt: !218)
!232 = !DILocation(line: 25, column: 23, scope: !167, inlinedAt: !218)
!233 = !DILocation(line: 25, column: 9, scope: !119, inlinedAt: !218)
!234 = !DILocation(line: 29, column: 10, scope: !142, inlinedAt: !218)
!235 = !DILocation(line: 30, column: 34, scope: !174, inlinedAt: !218)
!236 = !DILocation(line: 30, column: 9, scope: !119, inlinedAt: !218)
!237 = !DILocation(line: 29, column: 10, scope: !119, inlinedAt: !218)
!238 = !DILocation(line: 33, column: 13, scope: !178, inlinedAt: !218)
!239 = !DILocation(line: 33, column: 25, scope: !178, inlinedAt: !218)
!240 = !DILocation(line: 38, column: 21, scope: !185, inlinedAt: !218)
!241 = !DILocation(line: 38, column: 36, scope: !185, inlinedAt: !218)
!242 = !DILocation(line: 33, column: 9, scope: !119, inlinedAt: !218)
!243 = !DILocation(line: 41, column: 14, scope: !191, inlinedAt: !218)
!244 = !DILocation(line: 41, column: 19, scope: !191, inlinedAt: !218)
!245 = !DILocation(line: 60, column: 13, scope: !246)
!246 = distinct !DILexicalBlock(scope: !209, file: !3, line: 60, column: 9)
!247 = !DILocation(line: 59, column: 23, scope: !209)
!248 = !DILocation(line: 63, column: 20, scope: !209)
!249 = !{!193, !181, i64 6}
!250 = !DILocation(line: 64, column: 11, scope: !209)
!251 = !DILocation(line: 65, column: 42, scope: !209)
!252 = !DILocation(line: 65, column: 5, scope: !209)
!253 = !DILocation(line: 67, column: 1, scope: !209)
!254 = distinct !DISubprogram(name: "do_alert", scope: !3, file: !3, line: 70, type: !198, isLocal: false, isDefinition: true, scopeLine: 70, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !255)
!255 = !{!256, !257}
!256 = !DILocalVariable(name: "skb", arg: 1, scope: !254, file: !3, line: 70, type: !64)
!257 = !DILocalVariable(name: "srh", scope: !254, file: !3, line: 71, type: !33)
!258 = !DILocation(line: 70, column: 32, scope: !254)
!259 = !DILocation(line: 15, column: 45, scope: !119, inlinedAt: !260)
!260 = distinct !DILocation(line: 71, column: 29, scope: !254)
!261 = !DILocation(line: 17, column: 41, scope: !119, inlinedAt: !260)
!262 = !DILocation(line: 17, column: 30, scope: !119, inlinedAt: !260)
!263 = !DILocation(line: 17, column: 22, scope: !119, inlinedAt: !260)
!264 = !DILocation(line: 17, column: 11, scope: !119, inlinedAt: !260)
!265 = !DILocation(line: 18, column: 41, scope: !119, inlinedAt: !260)
!266 = !DILocation(line: 18, column: 30, scope: !119, inlinedAt: !260)
!267 = !DILocation(line: 18, column: 22, scope: !119, inlinedAt: !260)
!268 = !DILocation(line: 18, column: 11, scope: !119, inlinedAt: !260)
!269 = !DILocation(line: 16, column: 14, scope: !119, inlinedAt: !260)
!270 = !DILocation(line: 22, column: 23, scope: !163, inlinedAt: !260)
!271 = !DILocation(line: 22, column: 40, scope: !163, inlinedAt: !260)
!272 = !DILocation(line: 22, column: 9, scope: !119, inlinedAt: !260)
!273 = !DILocation(line: 25, column: 10, scope: !167, inlinedAt: !260)
!274 = !DILocation(line: 25, column: 23, scope: !167, inlinedAt: !260)
!275 = !DILocation(line: 25, column: 9, scope: !119, inlinedAt: !260)
!276 = !DILocation(line: 29, column: 10, scope: !142, inlinedAt: !260)
!277 = !DILocation(line: 30, column: 34, scope: !174, inlinedAt: !260)
!278 = !DILocation(line: 30, column: 9, scope: !119, inlinedAt: !260)
!279 = !DILocation(line: 29, column: 10, scope: !119, inlinedAt: !260)
!280 = !DILocation(line: 33, column: 13, scope: !178, inlinedAt: !260)
!281 = !DILocation(line: 33, column: 25, scope: !178, inlinedAt: !260)
!282 = !DILocation(line: 38, column: 21, scope: !185, inlinedAt: !260)
!283 = !DILocation(line: 38, column: 36, scope: !185, inlinedAt: !260)
!284 = !DILocation(line: 33, column: 9, scope: !119, inlinedAt: !260)
!285 = !DILocation(line: 41, column: 14, scope: !191, inlinedAt: !260)
!286 = !DILocation(line: 41, column: 19, scope: !191, inlinedAt: !260)
!287 = !DILocation(line: 72, column: 13, scope: !288)
!288 = distinct !DILexicalBlock(scope: !254, file: !3, line: 72, column: 9)
!289 = !DILocation(line: 71, column: 23, scope: !254)
!290 = !DILocation(line: 75, column: 60, scope: !254)
!291 = !{!193, !151, i64 5}
!292 = !DILocation(line: 75, column: 66, scope: !254)
!293 = !DILocation(line: 75, column: 5, scope: !254)
!294 = !DILocation(line: 76, column: 5, scope: !254)
!295 = !DILocation(line: 77, column: 1, scope: !254)
!296 = distinct !DISubprogram(name: "do_end_x", scope: !3, file: !3, line: 80, type: !198, isLocal: false, isDefinition: true, scopeLine: 80, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !297)
!297 = !{!298, !299, !300, !301}
!298 = !DILocalVariable(name: "skb", arg: 1, scope: !296, file: !3, line: 80, type: !64)
!299 = !DILocalVariable(name: "addr", scope: !296, file: !3, line: 81, type: !46)
!300 = !DILocalVariable(name: "hi", scope: !296, file: !3, line: 82, type: !49)
!301 = !DILocalVariable(name: "lo", scope: !296, file: !3, line: 83, type: !49)
!302 = !DILocation(line: 80, column: 32, scope: !296)
!303 = !DILocation(line: 81, column: 5, scope: !296)
!304 = !DILocation(line: 82, column: 24, scope: !296)
!305 = !DILocation(line: 83, column: 24, scope: !296)
!306 = !DILocation(line: 84, column: 10, scope: !296)
!307 = !DILocation(line: 84, column: 13, scope: !296)
!308 = !{!309, !182, i64 8}
!309 = !{!"in6_addr", !182, i64 0, !182, i64 8}
!310 = !DILocation(line: 85, column: 10, scope: !296)
!311 = !DILocation(line: 85, column: 13, scope: !296)
!312 = !{!309, !182, i64 0}
!313 = !DILocation(line: 81, column: 21, scope: !296)
!314 = !DILocation(line: 86, column: 5, scope: !296)
!315 = !DILocation(line: 88, column: 1, scope: !296)
!316 = !DILocation(line: 87, column: 5, scope: !296)
!317 = distinct !DISubprogram(name: "do_end_t", scope: !3, file: !3, line: 91, type: !198, isLocal: false, isDefinition: true, scopeLine: 91, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !318)
!318 = !{!319}
!319 = !DILocalVariable(name: "skb", arg: 1, scope: !317, file: !3, line: 91, type: !64)
!320 = !DILocation(line: 91, column: 32, scope: !317)
!321 = !DILocation(line: 92, column: 5, scope: !317)
!322 = !DILocation(line: 93, column: 5, scope: !317)
!323 = distinct !DISubprogram(name: "do_end_b6", scope: !3, file: !3, line: 97, type: !198, isLocal: false, isDefinition: true, scopeLine: 97, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !324)
!324 = !{!325, !326, !330, !331, !332, !333, !334}
!325 = !DILocalVariable(name: "skb", arg: 1, scope: !323, file: !3, line: 97, type: !64)
!326 = !DILocalVariable(name: "srh_buf", scope: !323, file: !3, line: 98, type: !327)
!327 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 320, elements: !328)
!328 = !{!329}
!329 = !DISubrange(count: 40)
!330 = !DILocalVariable(name: "srh", scope: !323, file: !3, line: 99, type: !33)
!331 = !DILocalVariable(name: "seg0", scope: !323, file: !3, line: 107, type: !53)
!332 = !DILocalVariable(name: "seg1", scope: !323, file: !3, line: 108, type: !53)
!333 = !DILocalVariable(name: "hi", scope: !323, file: !3, line: 109, type: !49)
!334 = !DILocalVariable(name: "lo", scope: !323, file: !3, line: 110, type: !49)
!335 = !DILocation(line: 97, column: 33, scope: !323)
!336 = !DILocation(line: 99, column: 23, scope: !323)
!337 = !DILocation(line: 98, column: 10, scope: !323)
!338 = !DILocation(line: 107, column: 22, scope: !323)
!339 = !DILocation(line: 108, column: 22, scope: !323)
!340 = !DILocation(line: 109, column: 24, scope: !323)
!341 = !DILocation(line: 110, column: 24, scope: !323)
!342 = !DILocation(line: 117, column: 14, scope: !323)
