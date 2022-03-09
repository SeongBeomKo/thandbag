package com.example.thandbag.controller;

import com.example.thandbag.dto.chat.ChatHistoryResponseDto;
import com.example.thandbag.dto.chat.ChatMyRoomListResponseDto;
import com.example.thandbag.dto.chat.chatroom.ChatRoomDto;
import com.example.thandbag.dto.chat.chatroom.CreateRoomRequestDto;
import com.example.thandbag.dto.login.LoginInfo;
import com.example.thandbag.security.UserDetailsImpl;
import com.example.thandbag.security.jwt.JwtTokenUtils;
import com.example.thandbag.service.ChatService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
public class ChatRoomController {

    private final ChatService chatService;
    private final JwtTokenUtils jwtTokenUtils;

    @GetMapping("/chat/user")
    public LoginInfo getUserInfo() {

        Authentication auth = SecurityContextHolder
                .getContext()
                .getAuthentication();

        UserDetailsImpl user = (UserDetailsImpl) auth.getPrincipal();
        String name = auth.getName();

        return LoginInfo.builder()
                .name(name)
                .token(jwtTokenUtils.
                        generateJwtToken(user, JwtTokenUtils.SEC * 1000))
                .build();
    }

    /* 내가 참가한 모든 채팅방 목록 */
    @GetMapping("/chat/myRoomList")
    public List<ChatMyRoomListResponseDto> room(
            @AuthenticationPrincipal UserDetailsImpl userDetails) {

        return chatService.findMyChatList(userDetails.getUser());
    }

    /* 채팅방 생성 */
    @PostMapping("/chat/room")
    public ChatRoomDto createRoom(@RequestBody CreateRoomRequestDto roomRequestDto) {
        return chatService.createChatRoom(roomRequestDto);
    }

    /* 채팅방 입장 화면 */
    @PostMapping("/chat/room/enter/{roomId}")
    public List<ChatHistoryResponseDto> roomDetail(@PathVariable String roomId) {
        return chatService.getTotalChatContents(roomId);
    }
}